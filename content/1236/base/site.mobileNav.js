$(document).ready(function () {
    var switched = false;

    var updateArticlePage = function () {

        var $destinations = $('[data-magellan-destination]');

        $destinations.removeClass('data-PaddingExtra');

        if (Modernizr.mq('only all and (max-width: 640px)') && !switched) {
            switched = true;

            if ($('.widget-BookJumpLinks').find('ul[data-magellan-expedition]').children().length > 1) {
                var $dropdown = $('.widget-BookChapterNavigation > .left-cell');
                $dropdown.append('<span class="down-arrow"><i class="icon-chevron-down"></i></span>');

                $('.left-cell').unbind('click').bind('click', function () {
                    $('#leftNavSticker').toggle();
                    setScrollHeight($('.widget-BookJumpLinks'));
                });

                $('.scrollTo').bind('click', function () {
                    // Tab-bar is hiding the title when it jumps to that section, so adding extra-padding dynamically so that you can see the padding
                    $('.scrollTo').removeClass('active');
                    $(this).addClass('active');
                    $destinations.removeClass('data-PaddingExtra');
                    $('#leftNavSticker').hide();

                    var id = $(this).attr('href').split('#')[1];
                    $('[data-magellan-destination="' + id + '"]').addClass('data-PaddingExtra');
                });

                $('.leftColumn').attr('style', '');
                $(window).off('scroll').on('scroll');
            }

            return true;
        }
        else if (Modernizr.mq('only all and (min-width: 640px)')) {
            if (switched) switched = false;
            $('.down-arrow').remove();

            // Preventing from Mobile Click event to happen on Tablet and Desktop view
            $('.scrollTo').unbind('click').bind('click');

            $('.widget-BookChapterNavigation > .left-cell');
            $('#leftNavSticker').show().removeClass('scroll-true');


            var iRightColumnHeight = $('.rightColumn').height();
            var iScrollMenu = $('#scrollMenu');
            var iScrollMenuHeight = iScrollMenu.height();
            var winHeight = $(window).height();
            var iScrollPos = 0;

            $(window).on('scroll', function () {
                if (Modernizr.mq('only all and (min-width: 640px)')) {
                    var iCurRightColumnHeight = $('.rightColumn').height();
                    if (iCurRightColumnHeight > iRightColumnHeight) {
                        $('.leftColumn').height(iCurRightColumnHeight);
                        iScrollMenu.trigger("sticky_kit:recalc");
                        $(document).foundation('magellan', 'reflow');
                    }

                    var iCurScrollPos = $(this).scrollTop();
                    if (iCurScrollPos > iScrollPos) { //Scrolling Down
                        if ((winHeight - iScrollMenuHeight) < 0) {
                            iScrollMenu.css('top', (winHeight - iScrollMenuHeight) + 'px');
                        }
                    } else { //Scrolling Up
                        iScrollMenu.css('top', '0px');
                    }
                    iScrollPos = iCurScrollPos;
                }
            });
        }
    };

    function setScrollHeight(elm) {

        var win = $(window);
        var bounds = elm.offset();

        var viewport = {
            top: win.scrollTop(),
            left: win.scrollLeft()
        };

        viewport.bottom = viewport.top + win.height();
        bounds.bottom = bounds.top + elm.outerHeight();

        var scrollHeight = viewport.bottom - bounds.top;

        // TODO: if menu height is greater than window height add scrollHeight 
        // else height = auto

        elm.find('ul').addClass('scroll-true').css('height', scrollHeight);
    }

    $(window).load(function () {
        updateArticlePage();
    });

    $(window).on("redraw", function () {
        switched = false; updateArticlePage();
        $("#scrollMenu").trigger("sticky_kit:recalc");
    }); // An event to listen for

    $(window).on("resize", function () {
        updateArticlePage();
        $("#scrollMenu").trigger("sticky_kit:recalc");
    });
});
