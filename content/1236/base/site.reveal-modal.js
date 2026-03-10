$(window).load(function () {
    $('.revealLink').on('click', function () {
        openRevealModal($('[content-id="' + $(this).attr('reveal-id') + '"]'));
    });

    $('.table-graphic').on('click', function () {
        openRevealModal($('[content-id="' + $(this).attr('data-id') + '"]'));
    });

    $('.caption-title').on('click', function () {

        var $childSection, $contentId;

        if ($(this).parents('.figure-section').size() > 0) {
            $contentId = $(this).parents('.figure-section').attr('data-id');
            $childSection = $('[content-id="' + $contentId + '"]');
        }
        else if ($(this).parents('.table-section').size() > 0) {
            $contentId = $(this).parents('.table-section').children('.table-graphic').attr('data-id');
            $childSection = $('[content-id="' + $contentId + '"]');
        }
        else if ($(this).parents('.video-section').size() > 0) {
            $contentId = $(this).parents('.video-section').attr('data-id');
            $childSection = $('[content-id="' + $contentId + '"]');
        }

        if ($childSection) openRevealModal($childSection);

    });

    $('.scrollable').on('scroll', function () {
        if ($(this).scrollLeft() > 0) alert($('.scrollable').scrollLeft());
    });
});

function openRevealModal($obj) {
    // $content is the child('figure-section') of [content-id] div
    $('#revealContent').empty().prepend($obj.children().clone());
    $('#revealModal').foundation('reveal', 'open');
}


// To Load figures inside the table
function revealOpened(){
    $(document).on('opened', '[data-reveal]', function () {
        var $modal = $(this);
        //triggerLazyLoad();

        $modal.find('.contentFigures').each(function () {
            $(this).attr('src', $(this).attr('data-original'));
        });
        figureRevealInsideTable($modal);
    });
}
revealOpened();


function figureRevealInsideTable($modal) {
    // It requires unbind first because of same class names in article tab, figure tab and the figure inside the table
    var contentID = $modal.find('[content-id="' + $(this).attr('reveal-id') + '"]');
    if (contentID.length > 0) { // the content is inside the current modal
        $modal.find('.revealLink').unbind().bind('click', function () {
            openRevealModal($modal.find('[content-id="' + $(this).attr('reveal-id') + '"]'));
        });
    } else { // else its a reveal modal link to another figure which is outside of current modal
        $('.revealLink').on('click', function () {
            var $content = $('[content-id="' + $(this).attr('reveal-id') + '"]');
            $content.find('.contentFigures').attr('src', $content.find('.contentFigures').attr('data-original'));
            openRevealModal($content);
        });
    }
    $modal.find('.caption-title').unbind().bind('click', function () {
        if ($(this).parents('.table-section').size() > 0) {
            if ($(this).parents('.figure-section').size() > 0) {
                var $contentId = $(this).parents('.figure-section').attr('data-id');
                var $childSection = $modal.find('[content-id="' + $contentId + '"]');
                if ($childSection) openRevealModal($childSection);
            }
        }
    });
}