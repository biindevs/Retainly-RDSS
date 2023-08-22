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
