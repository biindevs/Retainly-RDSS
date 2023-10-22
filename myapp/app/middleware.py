from django.http import HttpResponseRedirect
from django.urls import reverse

class ProfileCompletenessMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Check if the user is logged in and if their profile is not complete
        if request.user.is_authenticated and not request.user.userprofile.is_profile_complete:
            # Redirect the user to the profile creation page
            if request.path_info != reverse('create_candidate_profile'):
                return HttpResponseRedirect(reverse('create_candidate_profile'))

        response = self.get_response(request)
        return response
