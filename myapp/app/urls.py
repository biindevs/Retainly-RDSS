from django.urls import path, include
from . import views
from django.contrib.auth import views as auth_views


urlpatterns = [
    path('', views.index, name='index'),
    path('about/', views.about, name='about'),

    path('pdf/', views.pdf_test, name='pdf_test'),

    path('jobs/', views.jobs, name='jobs'),
    path('jobs/details/<int:job_id>/', views.job_details, name='job_details'),

    path('signin/', views.sign_in, name='sign_in'),
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


    path('user/resume', views.resume, name='resume'),

    path('user/addeducation', views.add_education, name='add_education'),
    path('user/editeducation/<int:education_id>/', views.edit_education, name='edit_education'),
    path('user/deleteeducation/<int:education_id>/', views.delete_education, name='delete_education'),

    path('user/addexperience', views.add_experience, name='add_experience'),
    path('user/editexperience/<int:workexperience_id>/', views.edit_experience, name='edit_experience'),
    path('user/deleteexperience/<int:workexperience_id>/', views.delete_experience, name='delete_experience'),

    path('user/addcertification', views.add_certification, name='add_certification'),
    path('user/editcertification<int:certification_id>/', views.edit_certification, name='edit_certification'),

    path('user/deletecertification/<int:certification_id>/', views.delete_certification, name='delete_certification'),


    path('user/addskill', views.add_skill, name='add_skill'),
    path('user/editskill/<int:skill_id>/', views.edit_skill, name='edit_skill'),
    path('user/deleteskill/<int:skill_id>/', views.delete_skill, name='delete_skill'),

    path('user/jobs/applied', views.candidate_jobs, name='candidate_jobs'),
    path('user/details', views.candidate_details, name='candidate_details'),
    path('user/changepassword', views.candidate_changepass, name='candidate_changepass'),
    path('employer/dashboard', views.employer_dashboard, name='employer_dashboard'),

    path('employer/profile', views.company_profile, name='company_profile'),
    path('employer/addprofile', views.addcompany_profile, name='addcompany_profile'),
    path('employer/editprofile', views.editcompany_profile, name='editcompany_profile'),

    path('employer/managejobs', views.manage_jobs, name='manage_jobs'),
    path('employer/jobs/<int:job_id>/', views.employer_jobs, name='employer_jobs'),
    path('employer/postjob', views.post_jobs, name='post_jobs'),
    path('employer/editjob/<int:job_id>/', views.edit_job, name='edit_job'),
    path('user/deletejob/<int:job_id>/', views.delete_job, name='delete_job'),

    path('employer/positions', views.positions, name='positions'),

    path('generate_pdf/', views.generate_pdf, name='generate_pdf'),


    path('employer/applicants', views.applicants, name='applicants'),
]

