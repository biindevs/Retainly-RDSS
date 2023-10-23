from django.http import HttpResponseRedirect
from django.urls import reverse

class ProfileCompletenessMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Check if the user is logged in
        if request.user.is_authenticated:
            if request.user.userprofile.role == "candidate" and request.path_info != reverse("create_candidate_profile"):
                # Redirect candidate users to the candidate profile creation page
                return HttpResponseRedirect(reverse("create_candidate_profile"))

        response = self.get_response(request)
        return response