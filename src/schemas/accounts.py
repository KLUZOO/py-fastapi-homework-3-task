from pydantic import BaseModel, EmailStr


class EmailPasswordMixinSchema(BaseModel):
    email: EmailStr
    password: str


class UserRegistrationRequestSchema(EmailPasswordMixinSchema):
    pass


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(EmailPasswordMixinSchema):
    token: str


class UserLoginRequestSchema(EmailPasswordMixinSchema):
    pass


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
