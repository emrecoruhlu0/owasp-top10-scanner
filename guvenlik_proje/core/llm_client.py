"""
core/llm_client.py

Ollama yerel LLM API'siyle haberleşen istemci.

Sorumluluklar:
  - Ham bulgu sözlüğünü insan-okunur bir prompt'a dönüştürmek.
  - Ollama /api/generate endpoint'ine POST atmak.
  - Yanıtı ayrıştırıp standart bir dict döndürmek.
  - Ollama erişilemez olduğunda graceful hata yönetimi sağlamak.

NOT: Bu modül ASLA zafiyet tespiti yapmaz. Yalnızca tespit sonrası
     doğrulama, risk analizi ve düzeltme önerisi üretir.
"""

from __future__ import annotations

import json
import logging
import re
import textwrap
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)

_OLLAMA_BASE_URL = "http://localhost:11434"
_DEFAULT_MODEL = "llama3"
_DEFAULT_TIMEOUT = 60  # LLM yanıtı için daha uzun bekleme

# Desteklenmeyen format durumunda döndürülecek güvenli varsayılan
_LLM_UNAVAILABLE: Dict[str, Any] = {
    "risk_seviyesi": "Bilinmiyor",
    "teknik_aciklama": "LLM yanıt vermedi veya erişilemez durumda.",
    "kod_duzeltme": "LLM erişilemez.",
    "genel_onlemler": [],
    "llm_guven": "Düşük",
    "llm_hatasi": True,
}


class LLMClient:
    """
    Ollama API istemcisi.

    Attributes:
        model: Ollama'da yüklü model adı (örn. "llama3.2:3b").
        base_url: Ollama sunucusunun temel URL'si.
        timeout: API çağrısı için saniye cinsinden bekleme süresi.
    """

    def __init__(
        self,
        model: str = _DEFAULT_MODEL,
        base_url: str = _OLLAMA_BASE_URL,
        timeout: int = _DEFAULT_TIMEOUT,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._generate_url = f"{self.base_url}/api/generate"

    # ------------------------------------------------------------------
    # Prompt oluşturma
    # ------------------------------------------------------------------

    def _build_prompt(self, finding: Dict[str, Any]) -> str:
        """
        Finding sözlüğünden yapılandırılmış bir analiz prompt'u üretir.

        Llama 3 gibi sohbet modelleri talimat verilmezse markdown bloğu
        veya açıklama metni ekler. Prompt; modeli saf JSON üretmeye
        zorlamak için şu teknikleri birlikte kullanır:
          1. "SYSTEM:" rolü bildirimi — model sohbet değil araç gibi davransın.
          2. Açık yasaklar — markdown, ``` blokları, açıklama metni yasak.
          3. Yanıtı doğrudan açan brace { ile başlama talimatı.
          4. Doldurulmuş şema örneği — modelin kopyalaması yeterli.
        """
        owasp_id   = finding.get("owasp_id",        "Bilinmiyor")
        title      = finding.get("title",            "Bilinmiyor")
        url        = finding.get("url",              "—")
        parameter  = finding.get("parameter",        "—")
        payload    = finding.get("payload",          "—")
        snippet    = finding.get("response_snippet", "—")
        confidence = finding.get("confidence",       "—")

        prompt = textwrap.dedent(f"""\
            SYSTEM: You are a JSON-only API endpoint for web security analysis.
            You MUST respond with a single raw JSON object.
            STRICT RULES — violation causes system failure:
              - Do NOT write any text before or after the JSON object.
              - Do NOT use markdown, code fences (```), or backticks.
              - Do NOT greet, explain, or comment.
              - Do NOT wrap output in an array.
              - Start your response with the opening brace: {{
              - End your response with the closing brace: }}

            INPUT (security finding to analyze):
            OWASP Category : {owasp_id} — {title}
            Target URL     : {url}
            Parameter      : {parameter}
            Payload used   : {payload}
            Detection conf : {confidence}
            Response snippet: {snippet}

            OUTPUT (copy this structure, fill every field, no extra keys):
            {{
              "risk_seviyesi": "Yüksek",
              "teknik_aciklama": "3 sentence max technical explanation.",
              "kod_duzeltme": "Specific fix or mitigation code/approach.",
              "genel_onlemler": ["measure 1", "measure 2", "measure 3"],
              "llm_guven": "Orta"
            }}

            Allowed values — risk_seviyesi: Kritik | Yüksek | Orta | Düşük | Bilgilendirici
            Allowed values — llm_guven: Yüksek | Orta | Düşük

            Respond NOW with only the JSON object:\
        """)

        return prompt

    # ------------------------------------------------------------------
    # API çağrısı
    # ------------------------------------------------------------------

    def query(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Bir Finding için Ollama'ya analiz isteği atar.

        Args:
            finding: base_module.Finding'den türetilmiş sözlük.

        Returns:
            LLM'den gelen ayrıştırılmış JSON yanıtı.
            Ollama erişilemezse _LLM_UNAVAILABLE sabiti döner.
        """
        prompt = self._build_prompt(finding)
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.2,  # Tutarlı, düşük yaratıcılıklı yanıt
                "num_predict": 512,
            },
        }

        try:
            logger.debug("LLM sorgusu gönderiliyor: model=%s, url=%s", self.model, self._generate_url)
            response = requests.post(
                self._generate_url,
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
            return self._parse_response(response.json())

        except requests.exceptions.ConnectionError:
            logger.warning(
                "Ollama'ya bağlanılamadı (%s). LLM analizi atlanıyor.", self._generate_url
            )
            return {**_LLM_UNAVAILABLE, "hata_nedeni": "Bağlantı hatası"}

        except requests.exceptions.Timeout:
            logger.warning("Ollama yanıt zaman aşımı (%ds).", self.timeout)
            return {**_LLM_UNAVAILABLE, "hata_nedeni": "Zaman aşımı"}

        except requests.exceptions.HTTPError as exc:
            logger.error("Ollama HTTP hatası: %s", exc)
            return {**_LLM_UNAVAILABLE, "hata_nedeni": str(exc)}

        except Exception as exc:  # noqa: BLE001
            logger.error("LLM sorgusunda beklenmeyen hata: %s", exc)
            return {**_LLM_UNAVAILABLE, "hata_nedeni": str(exc)}

    # ------------------------------------------------------------------
    # Yanıt ayrıştırma
    # ------------------------------------------------------------------

    def _parse_response(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ollama'nın ham yanıt zarfını açar ve içindeki JSON nesnesini döndürür.

        Ollama zarfı:
          {"model": "...", "response": "<model_çıktısı>", "done": true, ...}

        Model çıktısı; konuşma metni, markdown blokları veya saf JSON
        içerebilir. _extract_json() bu üç durumu sırayla dener.
        """
        response_text: str = raw.get("response", "")
        logger.debug("Ham LLM yanıtı (ilk 300 kar): %.300s", response_text)

        parsed = self._extract_json(response_text)
        if parsed is not None:
            parsed["llm_hatasi"] = False
            return parsed

        # Hiçbir strateji başarılı olmadı
        logger.warning(
            "LLM yanıtından JSON çıkarılamadı. Ham yanıt: %.300s", response_text
        )
        return {
            **_LLM_UNAVAILABLE,
            "hata_nedeni": "Geçersiz JSON yanıtı",
            "ham_yanit": response_text[:500],
        }

    def _extract_json(self, text: str) -> Optional[Dict[str, Any]]:
        """
        Serbest biçimli model çıktısından JSON nesnesini çıkarmak için
        dört stratejiyi sırayla dener; ilk başarılıda döner.

        Strateji 1 — Doğrudan ayrıştırma:
            Model kurala uydu ve saf JSON döndürdü.
        Strateji 2 — Markdown code fence soyma:
            ```json ... ``` veya ``` ... ``` bloğu içindeki metni al.
        Strateji 3 — Brace çıkarma (regex):
            Metindeki ilk { ile son } arasındaki alt dizeyi bul.
            Bu, "Here is the JSON:\n{...}" kalıplarını çözer.
        Strateji 4 — Satır satır tarama:
            { ile başlayan ilk satırı bul, oradan itibaren biriktir.
        """
        text = text.strip()

        # ---- Strateji 1: doğrudan ----------------------------------------
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # ---- Strateji 2: markdown code fence --------------------------------
        # ```json\n{...}\n```  veya  ```\n{...}\n```
        fence_match = re.search(
            r"```(?:json)?\s*(\{.*?\})\s*```",
            text,
            re.DOTALL | re.IGNORECASE,
        )
        if fence_match:
            candidate = fence_match.group(1).strip()
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass

        # ---- Strateji 3: ilk { … son } brace çıkarma ----------------------
        brace_match = re.search(r"\{.*\}", text, re.DOTALL)
        if brace_match:
            candidate = brace_match.group(0).strip()
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                # Brace eşleşmesi bulundu ama geçersiz JSON → yine de dene
                # (iç içe braces için greedy yerine en dış kapanışı bul)
                candidate = self._extract_outermost_braces(text)
                if candidate:
                    try:
                        return json.loads(candidate)
                    except json.JSONDecodeError:
                        pass

        # ---- Strateji 4: { ile başlayan satırdan itibaren biriktir ----------
        lines = text.splitlines()
        collecting = False
        buffer: list[str] = []
        depth = 0
        for line in lines:
            if not collecting and line.lstrip().startswith("{"):
                collecting = True
            if collecting:
                buffer.append(line)
                depth += line.count("{") - line.count("}")
                if depth <= 0:
                    break
        if buffer:
            candidate = "\n".join(buffer).strip()
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass

        return None  # Tüm stratejiler başarısız

    @staticmethod
    def _extract_outermost_braces(text: str) -> Optional[str]:
        """
        Metinde ilk açılan { ile ona karşılık gelen } arasındaki
        alt dizeyi karakter sayacıyla bulur.
        İç içe geçmiş brace'leri doğru işler.
        """
        start = text.find("{")
        if start == -1:
            return None
        depth = 0
        for i, ch in enumerate(text[start:], start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start: i + 1]
        return None

    # ------------------------------------------------------------------
    # Sağlık kontrolü
    # ------------------------------------------------------------------

    def health_check(self) -> bool:
        """Ollama sunucusunun ayakta olduğunu doğrular."""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=3)
            return resp.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def __repr__(self) -> str:
        return f"LLMClient(model={self.model!r}, base_url={self.base_url!r})"
