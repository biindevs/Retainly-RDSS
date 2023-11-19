// CLOSE OPEN PASSWORD FIELD

$(document).ready(function() {
    $('#job_description').summernote();
});

$(document).ready(function() {
    $('#skills_needed').select2({
        tags: true,
        tokenSeparators: [',', ' '], // Define how to separate tags (e.g., using ',' or ' ')
        placeholder: 'Enter skills', // Placeholder text
    });
});

$(document).ready(function() {
    $('#certification_needed').select2({
        tags: true,
        tokenSeparators: [',', ' '], // Define how to separate tags (e.g., using ',' or ' ')
        placeholder: 'Enter Certificates', // Placeholder text
    });
});


$(document).ready(function() {
    $('#myTabs a').click(function (e) {
        e.preventDefault();
        $(this).tab('show');
    });
    });

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


//DATE PICKER
document.addEventListener('DOMContentLoaded', function () {
    flatpickr('#birthdate', {
        dateFormat: 'Y-m-d',
        allowInput: true,
    });
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
    const deleteButtons = document.querySelectorAll('.delete-certification');

    deleteButtons.forEach(button => {
        button.addEventListener('click', function () {
            const certificationId = this.getAttribute('data-id');

            Swal.fire({
                title: "Oops!",
                text: "This action cannot be undone. Please confirm you want to proceed.",
                icon: "warning",
                showCancelButton: true,
                confirmButtonText: "Delete",
                cancelButtonText: "Cancel",
                dangerMode: true,
            }).then((result) => {
                if (result.isConfirmed) {
                    window.location.href = `/user/deletecertification/${certificationId}/`;
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

document.addEventListener('DOMContentLoaded', function () {
    const deleteButtons = document.querySelectorAll('.delete-jobs');

    deleteButtons.forEach(button => {
        button.addEventListener('click', function () {
            const jobId = this.getAttribute('data-id');


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

                    window.location.href = `/user/deletejob/${jobId}/`;
                } else {

                }
            });
        });
    });
});

document.addEventListener("DOMContentLoaded", function () {
    const currentlyWorkingCheckbox = document.getElementById("currently_working");
    const endMonthSelect = document.getElementById("end_month");
    const endYearSelect = document.getElementById("end_year");

    currentlyWorkingCheckbox.addEventListener("change", function () {
        const isCurrentlyWorking = this.checked;

        // Disable/enable the end date fields based on the checkbox's status
        endMonthSelect.disabled = isCurrentlyWorking;
        endYearSelect.disabled = isCurrentlyWorking;

        // If currently working, reset the end date fields
        if (isCurrentlyWorking) {
            endMonthSelect.value = "";
            endYearSelect.value = "";
        }
    });
});

// APPLIED JOBS
document.addEventListener('DOMContentLoaded', function () {
    var canvas = document.getElementById('applicationStatisticsChart');
    var ctx = canvas.getContext('2d');

    // Retrieve the job_id from the data attribute
    var job_id = canvas.getAttribute('data-job-id');

    // Define custom colors for each status
    var backgroundColors = {
        'Approved': 'rgba(75, 192, 192, 0.6)', // Green
        'Rejected': 'rgba(255, 99, 132, 0.6)',// Red
        'Pending': 'rgba(255, 206, 86, 0.6)', // Yellow
        'Withdrawn': 'rgba(128, 128, 128, 0.6)',  // Gray
    };

    // Fetch data from the Django endpoint with the dynamic job ID
    fetch(`/api/get_application_statistics/${job_id}/`)
        .then(response => response.json())
        .then(data => {
            var chartData = {
                labels: data.labels,
                datasets: [{
                    label: 'Applications',
                    data: data.counts,
                    backgroundColor: data.labels.map(label => backgroundColors[label]),
                    borderWidth: 1
                }]
            };

            var options = {
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            };

            var applicationStatisticsChart = new Chart(ctx, {
                type: 'bar',
                data: chartData,
                options: options
            });
        });
});
$(document).ready(function () {
    $('#education_level').change(function () {
        var selectedValue = $(this).val();
        if (selectedValue) {
            $('#educational_degree_field').show();
        } else {
            $('#educational_degree_field').hide();
        }
    });
});

function handleSpecializationChange(selectElement) {
    var otherSpecializationContainer = document.getElementById('otherSpecializationContainer');
    var otherSpecializationInput = document.getElementById('otherSpecialization');

    if (selectElement.value === 'Other') {
        otherSpecializationContainer.style.display = 'block';
        otherSpecializationInput.required = true;
    } else {
        otherSpecializationContainer.style.display = 'none';
        otherSpecializationInput.required = false;
    }
}

function handleEducationLevelChange(selectElement) {
    var educationDegreeContainer = document.getElementById('education_degree_container');

    if (selectElement.value !== '') {
        educationDegreeContainer.style.display = 'block';
    } else {
        educationDegreeContainer.style.display = 'none';
    }
}

document.getElementById("offered_salary").addEventListener("change", function() {
    var specificSalaryInput = document.getElementById("specific-salary-input");
    if (this.value === "specific") {
        specificSalaryInput.style.display = "block";
    } else {
        specificSalaryInput.style.display = "none";
    }
});








