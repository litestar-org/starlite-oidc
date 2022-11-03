import oic
from jwkest.jwk import SYMKey

signing_key = SYMKey(alg="HS256", key=oic.rndstr(), kid=oic.rndstr())
