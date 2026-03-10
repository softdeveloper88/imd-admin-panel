$(document).ready(function () {

    function isIE() {
        var myNav = navigator.userAgent.toLowerCase();
        return (myNav.indexOf('msie') != -1) ? parseInt(myNav.split('msie')[1]) : false;
    }

    

    $(window).load(function () {

        $('.linkToTop').on('click', function () {
            if ($('body').hasClass('active')) {
                $('#sidebarButton').trigger('click');
            }
            $('.widget-BookJumpLinks > ul >li.active').removeClass('active');
        });

        // Javascript trickery to get Get Citation Reveal modal to work
        //document.body.appendChild(document.getElementById('getCitation'));
        $('.widget-ToolboxGetCitation > a').on('click', function (e) {
            e.preventDefault();
            $('#getCitation').foundation('reveal', 'open');
        });

        if ($('.section-jump-link').size() == 0) {
            $('#leftNavSticker').addClass("no-jump-links");
        }

        // Math Data
        $('.math-data .disp-formula-data').each(function () {
            var $mathData = $(this).parent();
            var $span = $(this).children().find("span");
            if ($span.width() > $mathData.width()) {
                $mathData.addClass('wide-math');
            }
        });
        if (Modernizr.mq('only all and (min-width: 641px)')) {
            $('.math-reveal').on('click', function () {
                $('#mathRevealModal').empty().append($(this).prev('.math-section').find('.MathJax').clone());
            });
        }

        if (isIE() == 8) {
            // IE8 code
            $('[data-id]').each(function () {
                var $this = $(this).find('.caption-legend');
                if ($this.height() > 200) {
                    $this.css('overflow-y', 'scroll');
                } else {
                    $this.css('overflow-y', 'hidden');
                }
            });
        }

        $('#noAccessReveal').prepend($('#divPurchaseSubscriptionBox').clone());
        $('#noAccessReveal .hide-for-article-page').remove();
        $('#noAccessReveal .member-options .columns').removeAttr('style');
        $('.left-panel .box').height($('.left-panel').height() - 57);

        // Javascript that shows the Related Topics widget if there are topics. This is hidden by default.
        // Once more portlet column widgets are on the page, we'll need to make this code handle all of them.
        if ($('.widget-RelatedTopics > ul').children().length > 0) {
            $('.widget-RelatedTopics').closest('section').show();
        }

        // Javascript that shows the IN THIS ARTICLE heading if jumplinks exist.  Hidden by default.
        $('.widget-ArticleJumpLinks > ul').each(function () {
            if ($(this).children().length > 0) {
                $(this).closest('#leftNavSticker').show();
            };
        });

        /*toolbar Feature*/
        // Javascript that hides a tab link (i.e. figure tab link) if that tab has no contents.  
        // Compares class name of all the <li>'s under #filterDrop to the Div of that tab.
        $('.toolbox-menu').on('click', function () {
            $(this).addClass('clicked');
            $(this).siblings().removeClass('clicked');
        });

        $(document).on('click', function () {
            $('.toolbox-menu').each(function () {
                if (!$(this).find('ul').hasClass('open')) {
                    $(this).removeClass('clicked');
                }
            });
        });
    });
});

function showHideBox(lid) {
    $("div[data='" + lid + "'] .box-hidden").toggle();
    $("div[data='" + lid + "'] .box-displayed").toggle();
}
