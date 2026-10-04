"""
Form Extractor and Payload Generator for deep HTML form and API endpoint discovery.
Parses HTML forms, catalogs controls, handles HTML5 overrides and hidden method spoofing,
and synthesizes realistic dummy payloads for automated crawler exploration.
Built with pure Python standard library and BeautifulSoup4 for Termux / Linux portability.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Union
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from api_tool.models import DiscoveredEndpoint, DiscoveredParameter

logger = logging.getLogger(__name__)

# Method override names recognized by web frameworks (Rails, Laravel, Express, Spring, Symfony)
METHOD_OVERRIDE_FIELDS: Set[str] = {
    "_method",
    "_http_method",
    "x-http-method-override",
    "_http_method_override",
}

VALID_HTTP_METHODS: Set[str] = {
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "OPTIONS",
    "HEAD",
}


@dataclass
class FormControl:
    """Represents a single cataloged form control."""

    name: str
    control_type: str  # "input", "textarea", "select", "button"
    input_type: str = "text"
    value: Optional[str] = None
    required: bool = False
    checked: bool = False
    placeholder: Optional[str] = None
    options: List[str] = field(default_factory=list)
    selected_value: Optional[str] = None
    formaction: Optional[str] = None
    formmethod: Optional[str] = None
    formenctype: Optional[str] = None


class FormPayloadGenerator:
    """
    Synthesizes realistic dummy payloads for HTML form controls based on input type and field semantics.
    """

    EMAIL_DUMMY: str = "crawler@example.com"
    PASSWORD_DUMMY: str = "ApiToolTest123!"
    PHONE_DUMMY: str = "+1-555-0199"
    NUMBER_DUMMY: int = 1
    URL_DUMMY: str = "https://example.com"
    DATE_DUMMY: str = "2026-01-01"
    SEARCH_DUMMY: str = "test search"
    TEXT_DUMMY: str = "test"

    @classmethod
    def generate_value(cls, control: FormControl) -> Any:
        """Generates a realistic dummy value for a given form control."""
        # 1. Select controls
        if control.control_type == "select":
            if control.selected_value:
                return control.selected_value
            if control.options:
                return control.options[0]
            return "option1"

        # 2. Textarea controls
        if control.control_type == "textarea":
            if control.value:
                return control.value
            return "Test text description content."

        inp_type = control.input_type.lower()

        # 3. Hidden inputs
        if inp_type == "hidden":
            if control.value is not None and control.value != "":
                return control.value
            name_lower = control.name.lower()
            if any(k in name_lower for k in ("csrf", "token", "_token", "nonce", "authenticity")):
                return "test_csrf_token_value"
            return "hidden_value"

        # 4. Explicit semantic input types
        if inp_type == "email":
            return cls.EMAIL_DUMMY

        if inp_type == "password":
            return cls.PASSWORD_DUMMY

        if inp_type in ("tel", "phone"):
            return cls.PHONE_DUMMY

        if inp_type in ("number", "range"):
            if control.value and control.value.isdigit():
                return int(control.value)
            return cls.NUMBER_DUMMY

        if inp_type == "url":
            return cls.URL_DUMMY

        if inp_type == "date":
            return cls.DATE_DUMMY

        if inp_type in ("datetime-local", "datetime"):
            return "2026-01-01T12:00"

        if inp_type == "time":
            return "12:00"

        if inp_type == "month":
            return "2026-01"

        if inp_type == "week":
            return "2026-W01"

        if inp_type == "search":
            return cls.SEARCH_DUMMY

        if inp_type == "color":
            return "#ff0000"

        if inp_type == "file":
            return "sample_upload.txt"

        if inp_type == "checkbox":
            return control.value if control.value else "true"

        if inp_type == "radio":
            return control.selected_value or control.value or "option1"

        if inp_type == "submit" or control.control_type == "button":
            return control.value if control.value else "submit"

        # 5. Text & generic inputs: inspect prefilled value or name heuristics
        if control.value:
            return control.value

        n = control.name.lower()
        if "email" in n or "e-mail" in n:
            return cls.EMAIL_DUMMY
        if "pass" in n or "pwd" in n or "secret" in n:
            return cls.PASSWORD_DUMMY
        if "phone" in n or "tel" in n or "mobile" in n or "cell" in n:
            return cls.PHONE_DUMMY
        if "url" in n or "website" in n or "link" in n or "site" in n:
            return cls.URL_DUMMY
        if "date" in n or "dob" in n or "birth" in n:
            return cls.DATE_DUMMY
        if "search" in n or "query" in n or n in ("q", "s"):
            return cls.SEARCH_DUMMY
        if any(k in n for k in ("amount", "qty", "quantity", "count", "num", "price", "age", "year", "limit", "offset", "id")):
            return cls.NUMBER_DUMMY
        if any(k in n for k in ("user", "login", "author", "creator")):
            return "crawler_user"
        if any(k in n for k in ("first_name", "fname")):
            return "John"
        if any(k in n for k in ("last_name", "lname")):
            return "Doe"
        if any(k in n for k in ("name", "full_name")):
            return "John Doe"
        if any(k in n for k in ("addr", "street")):
            return "123 Main St"
        if "city" in n:
            return "Springfield"
        if any(k in n for k in ("zip", "postal", "postcode")):
            return "12345"

        return cls.TEXT_DUMMY

    @classmethod
    def generate_payload(cls, controls: List[FormControl]) -> Dict[str, Any]:
        """Synthesizes a realistic key-value dictionary payload from controls."""
        payload: Dict[str, Any] = {}
        for ctrl in controls:
            if not ctrl.name:
                continue
            payload[ctrl.name] = cls.generate_value(ctrl)
        return payload


class FormExtractor:
    """
    Extracts DiscoveredEndpoint models from HTML <form> elements.
    Handles hidden method overrides, control cataloging, button formaction/formmethod overrides,
    and realistic dummy payload synthesis.
    """

    @classmethod
    def extract(
        cls, soup: Union[BeautifulSoup, str], page_url: str
    ) -> List[DiscoveredEndpoint]:
        """
        Parses HTML forms and returns DiscoveredEndpoint models.
        """
        if isinstance(soup, str):
            soup = BeautifulSoup(soup, "html.parser")

        # 1. Resolve base URL from <base href="...">
        effective_base = page_url
        base_tag = soup.find("base")
        if base_tag and base_tag.get("href"):
            raw_base = str(base_tag.get("href")).strip()
            if raw_base:
                effective_base = urljoin(page_url, raw_base)

        discovered_endpoints: List[DiscoveredEndpoint] = []
        seen_keys: Set[Tuple[str, str]] = set()

        # 2. Iterate through all <form> tags
        for form in soup.find_all("form"):
            raw_action = form.get("action", "").strip()
            form_action = (
                urljoin(effective_base, raw_action) if raw_action else page_url
            )
            form_method = form.get("method", "GET").strip().upper() or "GET"
            raw_enctype = (
                form.get("enctype", "application/x-www-form-urlencoded")
                .strip()
                .lower()
                or "application/x-www-form-urlencoded"
            )
            form_enctype = cls._normalize_enctype(raw_enctype)

            # 3. Collect controls inside the form + HTML5 external controls via form id
            raw_elements = list(form.find_all(["input", "textarea", "select", "button"]))
            form_id = form.get("id")
            if form_id:
                external_controls = soup.find_all(
                    ["input", "textarea", "select", "button"],
                    attrs={"form": form_id},
                )
                for ext in external_controls:
                    if ext not in raw_elements:
                        raw_elements.append(ext)

            # 4. Detect hidden method overrides (_method, _http_method, x-http-method-override)
            effective_base_method = form_method
            for el in raw_elements:
                name = el.get("name", "").strip().lower()
                if name in METHOD_OVERRIDE_FIELDS:
                    override_val = el.get("value", "").strip().upper()
                    if override_val in VALID_HTTP_METHODS:
                        effective_base_method = override_val
                        break

            # 5. Catalog controls
            controls: List[FormControl] = []
            submit_buttons: List[FormControl] = []

            for el in raw_elements:
                tag_name = el.name.lower()
                name = el.get("name", "").strip()
                required = el.has_attr("required")
                placeholder = el.get("placeholder")

                if tag_name == "input":
                    inp_type = el.get("type", "text").strip().lower() or "text"
                    val = el.get("value")
                    checked = el.has_attr("checked")
                    fa = el.get("formaction")
                    fm = el.get("formmethod")
                    fe = el.get("formenctype")
                    ctrl = FormControl(
                        name=name,
                        control_type="input",
                        input_type=inp_type,
                        value=val,
                        required=required,
                        checked=checked,
                        placeholder=placeholder,
                        formaction=fa,
                        formmethod=fm.strip().upper() if fm else None,
                        formenctype=fe.strip().lower() if fe else None,
                    )
                    if inp_type in ("submit", "image"):
                        submit_buttons.append(ctrl)
                    else:
                        controls.append(ctrl)

                elif tag_name == "textarea":
                    val = el.text if el.text else el.get("value")
                    ctrl = FormControl(
                        name=name,
                        control_type="textarea",
                        input_type="textarea",
                        value=val,
                        required=required,
                        placeholder=placeholder,
                    )
                    controls.append(ctrl)

                elif tag_name == "select":
                    options: List[str] = []
                    selected_val: Optional[str] = None
                    for opt in el.find_all("option"):
                        opt_val = opt.get("value", opt.text.strip())
                        options.append(opt_val)
                        if opt.has_attr("selected"):
                            selected_val = opt_val
                    ctrl = FormControl(
                        name=name,
                        control_type="select",
                        input_type="select",
                        required=required,
                        options=options,
                        selected_value=selected_val,
                    )
                    controls.append(ctrl)

                elif tag_name == "button":
                    btn_type = el.get("type", "submit").strip().lower() or "submit"
                    val = el.get("value")
                    fa = el.get("formaction")
                    fm = el.get("formmethod")
                    fe = el.get("formenctype")
                    ctrl = FormControl(
                        name=name,
                        control_type="button",
                        input_type=btn_type,
                        value=val,
                        required=required,
                        formaction=fa,
                        formmethod=fm.strip().upper() if fm else None,
                        formenctype=fe.strip().lower() if fe else None,
                    )
                    if btn_type == "submit":
                        submit_buttons.append(ctrl)
                    else:
                        if name:
                            controls.append(ctrl)

            # 6. Generate primary form endpoint
            primary_endpoint = cls._build_endpoint(
                action=form_action,
                method=effective_base_method,
                enctype=form_enctype,
                controls=controls,
                submit_button=submit_buttons[0] if submit_buttons else None,
            )
            key = (primary_endpoint.full_url, primary_endpoint.method)
            if key not in seen_keys:
                seen_keys.add(key)
                discovered_endpoints.append(primary_endpoint)

            # 7. Generate button override endpoints (HTML5 formaction / formmethod)
            for btn in submit_buttons:
                if btn.formaction or btn.formmethod or btn.formenctype:
                    override_action = (
                        urljoin(effective_base, btn.formaction.strip())
                        if btn.formaction
                        else form_action
                    )
                    override_method = (
                        btn.formmethod.strip().upper()
                        if btn.formmethod
                        else effective_base_method
                    )
                    override_enctype = (
                        cls._normalize_enctype(btn.formenctype.strip().lower())
                        if btn.formenctype
                        else form_enctype
                    )

                    override_endpoint = cls._build_endpoint(
                        action=override_action,
                        method=override_method,
                        enctype=override_enctype,
                        controls=controls,
                        submit_button=btn,
                    )
                    ov_key = (
                        override_endpoint.full_url,
                        override_endpoint.method,
                    )
                    if ov_key not in seen_keys:
                        seen_keys.add(ov_key)
                        discovered_endpoints.append(override_endpoint)

        return discovered_endpoints

    @classmethod
    def _normalize_enctype(cls, enctype: str) -> str:
        if "multipart" in enctype:
            return "multipart/form-data"
        if "text/plain" in enctype:
            return "text/plain"
        return "application/x-www-form-urlencoded"

    @classmethod
    def _build_endpoint(
        cls,
        action: str,
        method: str,
        enctype: str,
        controls: List[FormControl],
        submit_button: Optional[FormControl] = None,
    ) -> DiscoveredEndpoint:
        """Constructs a DiscoveredEndpoint model with parameters and realistic payload."""
        all_controls = list(controls)
        if submit_button and submit_button.name:
            all_controls.append(submit_button)

        # Consolidate controls (e.g. radio buttons sharing the same name)
        consolidated_controls: List[FormControl] = []
        seen_radios: Dict[str, FormControl] = {}
        for ctrl in all_controls:
            if not ctrl.name:
                continue
            if ctrl.input_type == "radio":
                if ctrl.name in seen_radios:
                    existing = seen_radios[ctrl.name]
                    if ctrl.value:
                        existing.options.append(ctrl.value)
                    if ctrl.checked:
                        existing.selected_value = ctrl.value
                        existing.value = ctrl.value
                else:
                    if ctrl.value:
                        ctrl.options.append(ctrl.value)
                    if ctrl.checked:
                        ctrl.selected_value = ctrl.value
                    elif ctrl.value:
                        ctrl.selected_value = ctrl.value
                    seen_radios[ctrl.name] = ctrl
                    consolidated_controls.append(ctrl)
            else:
                consolidated_controls.append(ctrl)

        parameters: List[DiscoveredParameter] = []
        for ctrl in consolidated_controls:
            dummy_val = FormPayloadGenerator.generate_value(ctrl)
            location = "query" if method == "GET" else "body"

            if ctrl.input_type in ("number", "range"):
                param_type = "integer"
            elif ctrl.input_type == "checkbox":
                param_type = "boolean"
            else:
                param_type = "string"

            parameters.append(
                DiscoveredParameter(
                    name=ctrl.name,
                    location=location,
                    required=ctrl.required,
                    param_type=param_type,
                    example=dummy_val,
                    description=f"HTML form control type={ctrl.input_type}",
                )
            )

        headers: Dict[str, str] = {}
        request_body_sample: Optional[Dict[str, Any]] = None

        if method in ("POST", "PUT", "PATCH", "DELETE"):
            request_body_sample = FormPayloadGenerator.generate_payload(consolidated_controls)
            headers["Content-Type"] = enctype

        parsed = urlsplit(action)
        base_url = (
            f"{parsed.scheme}://{parsed.netloc}"
            if parsed.scheme and parsed.netloc
            else ""
        )
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        return DiscoveredEndpoint(
            path=path,
            method=method,
            base_url=base_url,
            source="crawler",
            tags=["form", method.lower()],
            parameters=parameters,
            request_body_sample=request_body_sample,
            headers=headers,
            summary=f"Form submission to {path} via {method}",
        )
