from django.urls import path, include
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', views.index, name='index'),
    path('sign-in/', views.sign_in, name='sign-in'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('sign-up/', views.sign_up, name='sign-up'),
    path('verify/<uuid:token>/', views.verify_email, name='verify_email'),
    path('google-signup/', views.google_signup, name='google_signup'),
    path('google-signup-redirect/', views.google_signup_redirect, name='google_signup_redirect'),
    # path('verification-pending/', views.verification_pending, name='verification_pending'),
]
