from pydantic import BaseModel


class TotpSetupResponse(BaseModel):
    secret: str
    otpauth_uri: str
    qr_code_data_uri: str


class TotpCodeRequest(BaseModel):
    code: str


class TotpDisableRequest(BaseModel):
    password: str


class WebauthnRegisterVerifyRequest(BaseModel):
    credential: dict


class MfaTokenRequest(BaseModel):
    mfa_token: str


class WebauthnLoginVerifyRequest(BaseModel):
    mfa_token: str
    credential: dict
