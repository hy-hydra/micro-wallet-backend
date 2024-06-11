"""
Django settings for central_wallet_backend project.

Generated by 'django-admin startproject' using Django 4.2.1.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

import os
from pathlib import Path
from datetime import timedelta
from dotenv import load_dotenv
load_dotenv()


# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-$@x=&#psdhg)8x#duf9u1@+($gptie!j(^hkci1&2l%vavkpe8'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = [
    'marcowallet.io',
    'test.marcowallet.io',
    'app.marcowallet.io',
    '127.0.0.1',
    '3.27.163.70',
    "localhost",
    '3.105.32.147',
    '52.65.42.73'
]


# Application definition

DJANGO_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'corsheaders',
    'rest_framework',
    "rest_framework_simplejwt",
    'crispy_forms'
]

CRISPY_ALLOWED_TEMPLATE_PACKS = "bootstrap5"

CRISPY_TEMPLATE_PACK = "bootstrap5"

LOCAL_APPS = [
    'user',
    'tokens',
    'transaction',
    'referral_system'
]

INSTALLED_APPS = DJANGO_APPS + LOCAL_APPS

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

CORS_ALLOWED_ORIGINS = [
    "http://localhost:5000",
    "http://127.0.0.1:5000",    
]

CORS_ALLOW_CREDENTIALS = True

ROOT_URLCONF = 'central_wallet_backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'central_wallet_backend.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'db_wallet',
        'USER': 'postgres',
        'PASSWORD': 'password1234',
        'HOST': '127.0.0.1',
        'PORT': '5432',
    }
}


# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

# TIME_ZONE = 'UTC'
TIME_ZONE = 'Asia/Dubai'


USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

AUTH_USER_MODEL = 'user.User'


SIMPLE_JWT = {
    # token expiration times
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=30),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
    # token rotation options
    # 'ROTATE_REFRESH_TOKENS': False,
    # 'BLACKLIST_AFTER_ROTATION': False,
    # user authentication options
    "AUTH_HEADER_TYPES": ("Bearer",),
    # 'USER_ID_FIELD': 'id',
    # 'USER_ID_CLAIM': 'user_id',
    # 'AUTH_TOKEN_CLASSES': (
    #     'rest_framework_simplejwt.tokens.AccessToken',
    #     'rest_framework_simplejwt.tokens.RefreshToken',
    # ),
    # 'TOKEN_TYPE_CLAIM': 'token_type',
    # token verification options
    # 'ALGORITHM': 'HS256',
    # 'SIGNING_KEY': None,
    # 'VERIFYING_KEY': None,
    # # token refresh options
    # 'ALLOW_REFRESH': True,
    # 'REFRESH_TOKEN_ROTATE_REFRESH_TOKENS': False,
    # 'REFRESH_TOKEN_BLACKLIST_AFTER_ROTATION': False,
    # 'UPDATE_LAST_LOGIN': False,
}


REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
}

NETWORK=os.getenv('NETWORK')

SYSTEM_ADMIN_EMAIL=os.getenv('SYSTEM_ADMIN_EMAIL')

# SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')
DEFAULT_FROM_EMAIL = os.getenv('FROM_EMAIL')

# EMAIL_BACKEND = "sendgrid_backend.SendgridBackend"

# EMAIL_BACKEND = 'django_ses.SESBackend'

AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
AWS_SES_REGION_NAME = os.getenv('AWS_SES_REGION_NAME')
# AWS_SES_REGION_ENDPOINT = os.getenv('AWS_SES_REGION_ENDPOINT')


LOGIN_REDIRECT_URL = 'success'

# Toggle sandbox mode (when running in DEBUG mode)

# echo to stdout or any other file-like object that is passed to the backend via the stream kwarg.
# SENDGRID_ECHO_TO_STDOUT=True

DOMAIN = os.getenv('DOMAIN')