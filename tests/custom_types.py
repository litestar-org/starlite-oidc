from typing import Dict, List, NamedTuple, Union

from oic.oic.message import IdToken

SessionStorage = Dict[str, Union[str, Dict[str, Union[List[str], int, str]]]]


class IdTokenStore(NamedTuple):
    id_token: IdToken
    id_token_jwt: str
