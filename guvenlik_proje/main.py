"""
main.py

AI Destekli Web Zafiyet Tarayıcısı – Ana Orkestratör

Kullanım:
  python main.py -u http://localhost/dvwa -o rapor.json
  python main.py -u http://localhost/dvwa --modules A03 --no-llm
  python main.py -u http://localhost/dvwa --llm-model llama3.2:3b --timeout 10
  python main.py -u http://localhost/dvwa --cookie "PHPSESSID=abc123; security=low"

Argümanlar:
  -u / --url       : Hedef web uygulaması URL'si (zorunlu)
  -o / --output    : Rapor çıktı dosyası (varsayılan: rapor.json)
  --modules        : Virgülle ayrılmış modül ID'leri veya "all" (varsayılan: all)
  --llm-model      : Ollama model adı (varsayılan: llama3.2:3b)
  --no-llm         : LLM analizini devre dışı bırak
  --timeout        : HTTP istek zaman aşımı saniye (varsayılan: 5)
  --proxy          : Proxy URL'si (örn. http://127.0.0.1:8080)
  --cookie         : Oturum çerezleri (örn. "PHPSESSID=abc123; security=low")
  --verbose        : Ayrıntılı log çıktısı
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.http_client import HTTPClient
from core.llm_client import LLMClient
from core.base_module import Finding
from modules.A01_BrokenAccessControl      import A01BrokenAccessControlModule
from modules.A02_CryptographicFailures    import A02CryptographicFailuresModule
from modules.A03_Injection                import A03InjectionModule
from modules.A04_InsecureDesign           import A04InsecureDesignModule
from modules.A05_SecurityMisconfiguration import A05SecurityMisconfigurationModule
from modules.A06_VulnerableComponents     import A06VulnerableComponentsModule
from modules.A07_IdentificationAuthFailures import A07IdentificationAuthFailuresModule
from modules.A08_DataIntegrity            import A08DataIntegrityModule
from modules.A09_LoggingMonitoring        import A09LoggingMonitoringModule
from modules.A10_SSRF                     import A10SSRFModule

# ---------------------------------------------------------------------------
# Kayıtlı modüller — çalıştırma sırasına göre OWASP Top 10
# ---------------------------------------------------------------------------

_MODULE_REGISTRY: Dict[str, type] = {
    "A01": A01BrokenAccessControlModule,
    "A02": A02CryptographicFailuresModule,
    "A03": A03InjectionModule,
    "A04": A04InsecureDesignModule,
    "A05": A05SecurityMisconfigurationModule,
    "A06": A06VulnerableComponentsModule,
    "A07": A07IdentificationAuthFailuresModule,
    "A08": A08DataIntegrityModule,
    "A09": A09LoggingMonitoringModule,
    "A10": A10SSRFModule,
}

_ALL_MODULES = list(_MODULE_REGISTRY.keys())


def setup_logging(verbose: bool) -> None:
    """Konsol log formatını ve seviyesini yapılandırır."""
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(name)s – %(message)s"
    logging.basicConfig(
        level=level,
        format=fmt,
        datefmt="%H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    # Requests ve urllib3 gürültüsünü bastır
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def parse_cookie_string(cookie_str: str) -> Dict[str, str]:
    """
    Tarayıcı formatındaki çerez dizesini anahtar-değer sözlüğüne çevirir.

    Örnek:
        "PHPSESSID=abc123; security=low" → {"PHPSESSID": "abc123", "security": "low"}

    Hatalı biçimdeki parçalar (= içermeyen) sessizce atlanır.
    """
    cookies: Dict[str, str] = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            cookies[key.strip()] = value.strip()
    return cookies


def parse_args() -> argparse.Namespace:
    """CLI argümanlarını ayrıştırır ve doğrular."""
    parser = argparse.ArgumentParser(
        prog="zafiyet-tarayici",
        description="AI Destekli Web Zafiyet Tarayıcısı (OWASP Top 10)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "-u", "--url",
        required=True,
        metavar="URL",
        help="Hedef web uygulamasının kök URL'si",
    )
    parser.add_argument(
        "-o", "--output",
        default="rapor.json",
        metavar="DOSYA",
        help="Rapor çıktı dosyası (varsayılan: rapor.json)",
    )
    parser.add_argument(
        "--modules",
        default="all",
        metavar="MODÜLLER",
        help=f"Çalıştırılacak modüller: all veya virgülle ayrılmış {_ALL_MODULES}",
    )
    parser.add_argument(
        "--llm-model",
        default="llama3",
        metavar="MODEL",
        help="Ollama model adı (varsayılan: llama3)",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="LLM analizini devre dışı bırak (yalnızca statik analiz)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        metavar="SANIYE",
        help="HTTP istek zaman aşımı (varsayılan: 5s)",
    )
    parser.add_argument(
        "--proxy",
        default=None,
        metavar="URL",
        help="Proxy URL'si (örn. http://127.0.0.1:8080)",
    )
    parser.add_argument(
        "--cookie",
        default=None,
        metavar="ÇEREZ",
        help=(
            'Oturum çerezleri; tarayıcıdan kopyalanabilir '
            '(örn. "PHPSESSID=abc123; security=low")'
        ),
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Ayrıntılı log çıktısı (DEBUG seviyesi)",
    )

    args = parser.parse_args()

    # Modül listesini doğrula
    if args.modules.lower() != "all":
        requested = [m.strip().upper() for m in args.modules.split(",")]
        unknown = [m for m in requested if m not in _MODULE_REGISTRY]
        if unknown:
            parser.error(
                f"Bilinmeyen modüller: {unknown}. "
                f"Mevcut modüller: {_ALL_MODULES}"
            )
        args.modules = requested
    else:
        args.modules = _ALL_MODULES

    return args


def resolve_modules(module_ids: List[str]) -> List[type]:
    """Modül ID listesinden sınıf listesi döndürür."""
    return [_MODULE_REGISTRY[mid] for mid in module_ids if mid in _MODULE_REGISTRY]


def run_scan(
    target: str,
    module_classes: List[type],
    http_client: HTTPClient,
    llm_client: Optional[LLMClient],
    enable_llm: bool,
    shared_data: Optional[Dict[str, Any]] = None,
) -> List[Finding]:
    """
    Tüm modülleri sırayla çalıştırır ve tüm bulguları birleştirir.

    Args:
        target        : Hedef URL.
        module_classes: Çalıştırılacak modül sınıfları listesi.
        http_client   : Paylaşılan HTTP istemcisi.
        llm_client    : LLM istemcisi (None → LLM atlanır).
        enable_llm    : LLM etkinleştirme bayrağı.
        shared_data   : Crawler çıktısı (opsiyonel).

    Returns:
        Tüm modüllerden toplanan Finding listesi.
    """
    all_findings: List[Finding] = []

    for ModuleClass in module_classes:
        module_name = getattr(ModuleClass, "OWASP_ID", ModuleClass.__name__)
        logger = logging.getLogger("orchestrator")
        logger.info("━" * 50)
        logger.info("Modül başlatılıyor: %s", module_name)

        try:
            # LLM destekli modüller için ekstra parametre geç
            init_kwargs: Dict[str, Any] = {
                "target": target,
                "http_client": http_client,
                "shared_data": shared_data or {},
            }
            if hasattr(ModuleClass, "enable_llm"):
                init_kwargs["llm_client"] = llm_client
                init_kwargs["enable_llm"] = enable_llm

            # A03 özelinde llm parametreleri direkt yapıcıya geçilir
            if ModuleClass is A03InjectionModule:
                init_kwargs["llm_client"] = llm_client
                init_kwargs["enable_llm"] = enable_llm

            module = ModuleClass(**init_kwargs)
            findings = module.run()
            all_findings.extend(findings)
            logger.info(
                "Modül tamamlandı: %s → %d bulgu", module_name, len(findings)
            )

        except Exception as exc:
            logging.getLogger("orchestrator").error(
                "Modül %s hata verdi: %s", module_name, exc, exc_info=True
            )

    return all_findings


def build_report(
    target: str,
    findings: List[Finding],
    modules_run: List[str],
    scan_duration: float,
    llm_enabled: bool,
    llm_model: str,
) -> Dict[str, Any]:
    """Tüm bulgulardan JSON raporunu oluşturur."""
    severity_counts: Dict[str, int] = {}
    for f in findings:
        sev = f.severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "scan_info": {
            "target": target,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "duration_seconds": round(scan_duration, 2),
            "modules_run": modules_run,
            "llm_enabled": llm_enabled,
            "llm_model": llm_model if llm_enabled else None,
            "tool": "AI-Destekli Web Zafiyet Tarayıcısı v1.0",
        },
        "summary": {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
        },
        "findings": [f.to_dict() for f in findings],
    }


def save_report(report: Dict[str, Any], output_path: str) -> None:
    """Raporu JSON dosyasına yazar."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)


def print_summary(findings: List[Finding]) -> None:
    """Tarama tamamlandığında konsola özet tablosu basar."""
    log = logging.getLogger("orchestrator")
    log.info("━" * 50)
    log.info("TARAMA ÖZETI")
    log.info("━" * 50)

    if not findings:
        log.info("Hiçbir bulgu tespit edilmedi.")
        return

    for i, f in enumerate(findings, 1):
        llm_risk = ""
        if f.llm_analysis and not f.llm_analysis.get("llm_hatasi"):
            llm_risk = f" | LLM Risk: {f.llm_analysis.get('risk_seviyesi', '?')}"
        log.info(
            "[%d] %s | %s | %s%s",
            i,
            f.owasp_id,
            f.title,
            f.confidence.value,
            llm_risk,
        )


def main() -> int:
    """Ana giriş noktası. Çıkış kodu: 0=başarı, 1=hata, 2=bulgu var."""
    args = parse_args()
    setup_logging(args.verbose)
    log = logging.getLogger("orchestrator")

    log.info("=" * 60)
    log.info("AI Destekli Web Zafiyet Tarayıcısı")
    log.info("Hedef   : %s", args.url)
    log.info("Modüller: %s", ", ".join(args.modules))
    log.info("LLM     : %s", "Devre dışı" if args.no_llm else args.llm_model)
    log.info("Oturum  : %s", "Çerez sağlandı" if args.cookie else "Anonim (çerez yok)")
    log.info("=" * 60)

    # Çerez dizesini ayrıştır
    session_cookies: Dict[str, str] = {}
    if args.cookie:
        session_cookies = parse_cookie_string(args.cookie)
        if not session_cookies:
            log.warning("--cookie argümanı ayrıştırılamadı; çerez gönderilmeyecek.")
        else:
            log.info("Oturum çerezleri yüklendi: %s", list(session_cookies.keys()))

    # İstemcileri başlat
    http_client = HTTPClient(
        timeout=args.timeout,
        proxy=args.proxy,
        cookies=session_cookies or None,
    )
    llm_client: Optional[LLMClient] = None

    if not args.no_llm:
        llm_client = LLMClient(model=args.llm_model)
        if not llm_client.health_check():
            log.warning(
                "Ollama sunucusuna erişilemiyor. "
                "LLM analizi atlanacak (--no-llm ile susturabilirsiniz)."
            )
            llm_client = None

    # Modülleri çöz
    module_classes = resolve_modules(args.modules)
    if not module_classes:
        log.error("Çalıştırılacak modül bulunamadı.")
        return 1

    # Taramayı çalıştır
    start_time = time.monotonic()
    try:
        findings = run_scan(
            target=args.url,
            module_classes=module_classes,
            http_client=http_client,
            llm_client=llm_client,
            enable_llm=(not args.no_llm),
        )
    except KeyboardInterrupt:
        log.warning("Tarama kullanıcı tarafından durduruldu.")
        return 1
    finally:
        http_client.close()

    duration = time.monotonic() - start_time

    # Özet ve rapor
    print_summary(findings)

    report = build_report(
        target=args.url,
        findings=findings,
        modules_run=args.modules,
        scan_duration=duration,
        llm_enabled=(not args.no_llm) and (llm_client is not None),
        llm_model=args.llm_model,
    )
    save_report(report, args.output)
    log.info("Rapor kaydedildi: %s", args.output)
    log.info("Toplam süre: %.2fs", duration)

    return 2 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
