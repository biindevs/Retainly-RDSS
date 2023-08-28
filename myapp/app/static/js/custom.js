// CLOSE OPEN PASSWORD FIELDS
document.addEventListener("DOMContentLoaded", function () {
    const passwordField = document.getElementById("password");
    const confirmPasswordField = document.getElementById("confirmPassword");
    const togglePasswordIcon = document.getElementById("togglePassword");

    function togglePasswordVisibility() {
        const fieldType = passwordField.type === "password" ? "text" : "password";
        passwordField.type = fieldType;
        confirmPasswordField.type = fieldType;

        const icon = passwordField.type === "password" ? '<i data-feather="eye"></i>' : '<i data-feather="eye-off"></i>';
        togglePasswordIcon.innerHTML = icon;

        feather.replace();
    }

    togglePasswordIcon.addEventListener("click", togglePasswordVisibility);
});


// IMAGE CAROUSEL IN THE FEATURES PAGES
$(document).ready(function(){
    $(".owl-carousel").owlCarousel({
        margin: 20,
        loop: true,
        nav: false,
        dots: false,
        responsive: {
            0: {
                items: 1
            },
            600: {
                items: 2
            },
            1000: {
                items: 3
            }
        }
    });

    $("#customPrev").click(function(){
        $(".owl-carousel").trigger('prev.owl.carousel');
    });

    $("#customNext").click(function(){
        $(".owl-carousel").trigger('next.owl.carousel');
    });
});


