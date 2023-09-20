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

function hideErrorMessage() {
    setTimeout(function () {
        var errorMessage = document.getElementById("error_messages");
        if (errorMessage) {
            errorMessage.style.display = "none";
        }
    }, 10000); // 10 seconds (10,000 milliseconds)
}

// Call the function when the page loads to start the timer
window.onload = hideErrorMessage;

// Call the function when the page is reloaded
window.onbeforeunload = function () {
    hideErrorMessage();
};

$(function() {
    $("#deadline-date").datepicker();
});

document.addEventListener('DOMContentLoaded', function () {
    const deleteButtons = document.querySelectorAll('.delete-education');

    deleteButtons.forEach(button => {
        button.addEventListener('click', function () {
            const educationId = this.getAttribute('data-id');


            Swal.fire({
                title: "Oops! ",
                text: "This action cannot be undone. Please confirm you want to proceed.",
                icon: "warning",
                showCancelButton: true,
                confirmButtonText: "Delete",
                cancelButtonText: "Cancel",
                dangerMode: true,
            }).then((result) => {
                if (result.isConfirmed) {

                    window.location.href = `/user/deleteeducation/${educationId}/`;
                } else {

                }
            });
        });
    });
});



document.addEventListener('DOMContentLoaded', function () {
    const deleteButtons = document.querySelectorAll('.delete-experience');

    deleteButtons.forEach(button => {
        button.addEventListener('click', function () {
            const experienceId = this.getAttribute('data-id');


            Swal.fire({
                title: "Oops! ",
                text: "This action cannot be undone. Please confirm you want to proceed.",
                icon: "warning",
                showCancelButton: true,
                confirmButtonText: "Delete",
                cancelButtonText: "Cancel",
                dangerMode: true,
            }).then((result) => {
                if (result.isConfirmed) {

                    window.location.href = `/user/deleteexperience/${experienceId}/`;
                } else {

                }
            });
        });
    });
});


document.addEventListener('DOMContentLoaded', function () {
    const deleteButtons = document.querySelectorAll('.delete-award');

    deleteButtons.forEach(button => {
        button.addEventListener('click', function () {
            const awardId = this.getAttribute('data-id');


            Swal.fire({
                title: "Oops! ",
                text: "This action cannot be undone. Please confirm you want to proceed.",
                icon: "warning",
                showCancelButton: true,
                confirmButtonText: "Delete",
                cancelButtonText: "Cancel",
                dangerMode: true,
            }).then((result) => {
                if (result.isConfirmed) {

                    window.location.href = `/user/deleteaward/${awardId}/`;
                } else {

                }
            });
        });
    });
});

document.addEventListener('DOMContentLoaded', function () {
    const deleteButtons = document.querySelectorAll('.delete-skill');

    deleteButtons.forEach(button => {
        button.addEventListener('click', function () {
            const skillId = this.getAttribute('data-id');


            Swal.fire({
                title: "Oops! ",
                text: "This action cannot be undone. Please confirm you want to proceed.",
                icon: "warning",
                showCancelButton: true,
                confirmButtonText: "Delete",
                cancelButtonText: "Cancel",
                dangerMode: true,
            }).then((result) => {
                if (result.isConfirmed) {

                    window.location.href = `/user/deleteskill/${skillId}/`;
                } else {

                }
            });
        });
    });
});

// Update the label text with the selected file's name
function updateFileNameLabel(input) {

    const fileName = input.files[0] ? input.files[0].name : 'Choose file';

    const label = input.nextElementSibling;
    label.textContent = fileName;
}








