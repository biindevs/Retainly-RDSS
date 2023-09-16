from django.urls import path, include
from . import views
from django.contrib.auth import views as auth_views


urlpatterns = [
    path('', views.index, name='index'),
    path('about/', views.about, name='about'),
    path('jobs/', views.jobs, name='jobs'),
    path('jobs/details', views.jobdetails, name='jobdetails'),
    path('sign-in/', views.sign_in, name='sign-in'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('sign-up/', views.sign_up, name='sign-up'),
    path('verify/<uuid:token>/', views.verify_email, name='verify_email'),
    path('google-signup/', views.google_signup, name='google_signup'),
    path('google-signup-redirect/', views.google_signup_redirect, name='google_signup_redirect'),
    path('view-profile', views.viewprofile, name='view-profile'),
    path('edit-profile', views.editprofile, name='edit-profile'),
    # path('verification-pending/', views.verification_pending, name='verification_pending'),
    path('signin/', views.signin, name='signin'),
    path('user/dashboard', views.candidate_dashboard, name='candidate_dashboard'),
    path('user/profile', views.view_profile, name='view_profile'),
    path('user/addprofile', views.add_profile, name='add_profile'),
    path('user/editprofile', views.edit_profile, name='edit_profile'),
    path('user/resume', views.candidate_resume, name='candidate_resume'),
    path('user/jobs/applied', views.candidate_jobs, name='candidate_jobs'),
    path('user/details', views.candidate_details, name='candidate_details'),
    path('user/changepassword', views.candidate_changepass, name='candidate_changepass'),
    path('employer/dashboard', views.employer_dashboard, name='employer_dashboard'),
    path('employer/profile', views.company_profile, name='company_profile'),
    path('employer/postjobs', views.post_jobs, name='post_jobs'),
    path('employer/managejobs', views.manage_jobs, name='manage_jobs'),
    path('employer/applicants', views.applicants, name='applicants'),
]

