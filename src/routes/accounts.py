from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from schemas.accounts import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == user.email))
    db_user = result.scalar_one_or_none()
    if db_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user.email} already exists."
        )
    result = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    db_user_groups = result.scalar_one_or_none()

    if not db_user_groups:
        db_user_groups = UserGroupModel(name=UserGroupEnum.USER)
        db.add(db_user_groups)
        await db.commit()
        await db.refresh(db_user_groups)
    try:
        db_user = UserModel.create(
            email=user.email,
            raw_password=user.password,
            group_id=db_user_groups.id,
        )

        activation_token = ActivationTokenModel(
            user=db_user
        )
        db.add(db_user)
        db.add(activation_token)
        await db.commit()
        await db.refresh(db_user)
    except ValueError as error:
        await db.rollback()
        raise HTTPException(
            status_code=422,
            detail=str(error)
        )
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )

    return {
        "id": db_user.id,
        "email": db_user.email,
    }


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_user(
        user: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserModel)
        .options(selectinload(UserModel.activation_token))
        .where(UserModel.email == user.email)
    )
    db_user = result.scalar_one_or_none()
    if not db_user:
        raise HTTPException(
            status_code=404,
            detail=f"User with email {user.email} does not exist."
        )
    if db_user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )
    if db_user.activation_token is None or user.token is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )
    activation_token = db_user.activation_token
    expires_at = cast(datetime, activation_token.expires_at).replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)

    if (
            activation_token.token != user.token
            or expires_at <= now
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )
    db_user.is_active = True
    await db.delete(activation_token)
    await db.commit()
    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def password_reset_request(
        payload: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    try:
        result = await db.execute(
            select(UserModel)
            .options(selectinload(UserModel.password_reset_token))
            .where(UserModel.email == payload.email)
        )
        db_user = result.scalar_one_or_none()
        if db_user and db_user.is_active:
            if db_user.password_reset_token:
                await db.delete(db_user.password_reset_token)

            password_reset_token = PasswordResetTokenModel(user=db_user)
            db.add(password_reset_token)
            await db.commit()
    except SQLAlchemyError:
        await db.rollback()
    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def reset_password(
        payload: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserModel)
        .options(selectinload(UserModel.password_reset_token))
        .where(UserModel.email == payload.email)
    )
    db_user = result.scalar_one_or_none()
    if not db_user or not db_user.is_active:
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )
    password_reset_token = db_user.password_reset_token
    if not password_reset_token:
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )
    expires_at = cast(datetime, password_reset_token.expires_at).replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if (
            password_reset_token.token != payload.token
            or expires_at <= now
    ):
        await db.delete(password_reset_token)
        await db.commit()
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )

    try:
        db_user.password = payload.password
        await db.delete(password_reset_token)
        await db.commit()
        return {"message": "Password reset successfully."}
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login(
        user: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings),

):
    result = await db.execute(
        select(UserModel)
        .where(UserModel.email == user.email)
    )
    db_user = result.scalar_one_or_none()
    if not db_user or not db_user.verify_password(user.password):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password."
        )
    if not db_user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is not activated."
        )
    days_valid_refresh_token = settings.LOGIN_TIME_DAYS
    refresh_token = jwt_manager.create_refresh_token(
        data={
            "user_id": db_user.id,
        },
        expires_delta=timedelta(days=days_valid_refresh_token),
    )
    refresh_token_model = RefreshTokenModel.create(
        user_id=db_user.id,
        days_valid=days_valid_refresh_token,
        token=refresh_token
    )
    access_token = jwt_manager.create_access_token(
        data={
            "user_id": db_user.id,
        }
    )
    try:
        db.add(refresh_token_model)
        await db.commit()
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request."
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
)
async def refresh(
        payload: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        refresh_token = jwt_manager.decode_refresh_token(payload.refresh_token)
    except BaseSecurityError:
        raise HTTPException(
            status_code=400,
            detail="Token has expired."
        )
    result = await db.execute(
        select(RefreshTokenModel)
        .where(RefreshTokenModel.token == payload.refresh_token)
    )
    db_refresh_token = result.scalar_one_or_none()
    if not db_refresh_token:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found."
        )
    if db_refresh_token.user_id != refresh_token["user_id"]:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token."
        )
    result = await db.execute(
        select(UserModel)
        .where(UserModel.id == refresh_token["user_id"])
    )
    db_user = result.scalar_one_or_none()
    if not db_user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )
    access_token = jwt_manager.create_access_token(
        data={
            "user_id": db_user.id,
        }
    )
    return {
        "access_token": access_token,
    }
