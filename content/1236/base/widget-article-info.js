$(document).ready(function () {
    var switched = false;
    var updateWidget = function () {
        var elmArr = ['#relatedContentWidgetSection', '#articleInfo'];
        var i, ati;

        if (($(window).width() < 767) && !switched) {
            switched = true;
            for (i = 0; i < elmArr.length; i++) {
                ati = $(elmArr[i].toString()).children('.section-container');
                if (!ati.hasClass('accordion')) {
                    ati.addClass('accordion')
                        .attr('data-section', 'accordion')
                        .attr('data-options', 'one_up: false');
                }
            }
            $('#relatedContentWidgets > section').each(function () {
                $(this).addClass('open');
            });
        }
        else if ($(window).width() > 767) {
            if (switched) switched = false;
            for (i = 0; i < elmArr.length; i++) {
                ati = $(elmArr[i].toString()).children('.section-container');
                if (ati.hasClass('accordion')) {
                    ati.removeClass('accordion')
                        .removeAttr('data-section')
                        .removeAttr('data-options');
                }
            }
            $('#relatedContentWidgets > section').each(function () {
                $(this).addClass('open');
            });

        }



        return true;
    };

    $('#relatedContentWidgets > section').each(function () {
        $(this).on('click', function () {
            if ($(window).width() > 767) $(this).toggleClass('open');
        });
    });


    $(window).load(function () {
        updateWidget();
        
        $('.toggle-affiliation').on('click', function () {
            $('.toggle-affiliation > i').toggleClass('icon-minus icon-plus');
            $('.wi-affiliationList').toggleClass('hide');
        });

    });
    $(window).on("redraw", function () { switched = false; updateWidget(); }); // An event to listen for
    $(window).on("resize", function () { updateWidget(); });

});