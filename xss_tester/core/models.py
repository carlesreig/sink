from pydantic import BaseModel
from typing import Optional, Dict, List


class Form(BaseModel):
    action: str
    method: str
    fields: Dict[str, Optional[str]]
    injectable_fields: List[str]


class InjectionPoint(BaseModel):
    form: Optional[Form] = None
    url: str
    method: str
    parameter: str
    source: str
    context: Optional[str] = None
    subcontext: Optional[str] = None
    risk_score: int = 0
    attack_surface: str = "main"  # main, iframe
    confidence: str = "certain"   # certain, potential


class Payload(BaseModel):
    value: str
    category: str

    # Context esperat (HTML, attribute, JS, DOM, etc.)
    expected_context: Optional[str] = None
    expected_subcontext: Optional[str] = None

    # events necessaris per executar el payload
    # Ex: ["ontoggle"], ["onmouseover"], ["onfocus"]
    requires: List[str] = []


class Finding(BaseModel):
    injection_point: InjectionPoint
    payload: Payload
    reflected: bool = False
    executed: bool = False
    evidence: Optional[str] = None
