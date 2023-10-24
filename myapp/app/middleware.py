from django.http import HttpResponseRedirect
from django.urls import reverse

class ProfileCompletenessMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            user_profile = request.user.userprofile
            current_path = request.path_info

            # Check if the user's profile is incomplete
            if not user_profile.is_profile_complete:
                if user_profile.role == "candidate" and not current_path.startswith("/user/createprofile"):
                    # Redirect candidate users to the candidate profile creation page
                    return HttpResponseRedirect(reverse("create_candidate_profile"))
                elif user_profile.role == "employer" and not current_path.startswith("/employer/createprofile"):
                    # Redirect employer users to the employer profile creation page
                    return HttpResponseRedirect(reverse("create_employer_profile"))

        response = self.get_response(request)
        return response
