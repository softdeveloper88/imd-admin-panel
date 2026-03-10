$(window).on("load", function () {
    var contentToolbar = contentToolbar || {};

    // equal height function
    contentToolbar.equalHeight = function (elm, classname, option) {

        $(elm).each(function () {
            if (classname) {
                var $columns = $(this).children(classname, this);
            } else {
                var $columns = $(this).children('section', this);
            }

            var maxHeight = Math.max.apply(Math, $columns.children().map(function () {
                return $(this).height();
            }).get());

            //if (extraHeight) maxHeight = maxHeight + extraHeight;

            if (option) {
                $(option).height(maxHeight);
            } else {
                $columns.height(maxHeight);
            }

        });
    };

    // toolbar filter functions
    contentToolbar.filterContentView = function (contentFilter) {
        var contentContainer = $('#articleTab').find('.widget-BookSectionsText > .module-widget');

        //reset filtered view
        $(contentContainer).children('.widget-items[data-content-filter]').remove();

        var fullContent = $(contentContainer).children('.widget-items');

        if (contentFilter === 'all') {
            $(fullContent).show();
        }
        else {
            $(fullContent).hide();

            //build a filtered view
            var filteredContent;

            if (contentFilter === 'figure') {
                filteredContent = $(fullContent).find('.figure-section');
            } else if (contentFilter === 'table') {
                filteredContent = $(fullContent).find('.table-section');
            } else if (contentFilter === 'video') {
                filteredContent = $(fullContent).find('.video-section');
            }

            if (filteredContent != null && filteredContent.length > 0) {
                // remove hidden and dup items
                filteredContent = filteredContent.filter(function () {
                    return $(this).parent().is(":not(.hide)");
                });

                var filteredView = $('<div class="widget-items" data-content-filter="' + contentFilter + '"></div>').append(filteredContent.clone(true));
                $(contentContainer).append(filteredView);
            }
        }

        triggerLazyLoad();
    };

    // set "View" filters
    contentToolbar.filter = function () {

        var contentItems = $('#articleTab').find('.widget-BookSectionsText > .module-widget > .widget-items');
        var contentFilters = $('ul#filterDrop').children('li');
        var filtersCount = $(contentFilters).length;

        if ($(contentItems).find('.figure-section').length == 0) {
            $(contentFilters).filter('[data-content-filter="figure"]').remove();
            filtersCount--;
        }
        if ($(contentItems).find('.table-section').length == 0) {
            $(contentFilters).filter('[data-content-filter="table"]').remove();
            filtersCount--;
        }

        if ($(contentItems).find('.video-section').length == 0) {
            $(contentFilters).filter('[data-content-filter="video"]').remove();
            filtersCount--;
        }

        if (filtersCount <= 1) {
            $('ul#filterDrop').closest('.menu-icon').remove();
            if (Modernizr.mq('only all and (min-width: 640px)')) contentToolbar.equalHeight('.main-section > .row', '.columns', '.leftColumn');
        } else {
            $(contentFilters).on('click', function () {
                contentToolbar.filterContentView($(this).attr('data-content-filter'));
                $(this).closest('.toolbox-menu').click(); //close dropdown

                if (Modernizr.mq('only all and (min-width: 1024px)')) contentToolbar.equalHeight('.main-section > .row', '.columns', '.leftColumn');
            });
        }
    };

    contentToolbar.preloadimages = function(arr) {
        var newimages = [], loadedimages = 0;
        var postaction = function () { };
        var arr = (typeof arr != "object") ? [arr] : arr;
        function imageloadpost() {
            loadedimages++;
            if (loadedimages == arr.length) {
                postaction(newimages); //call postaction and pass in newimages array as parameter
            }
        }
        for (var i = 0; i < arr.length; i++) {
            newimages[i] = new Image();
            newimages[i].src = arr[i];
            newimages[i].onload = function () {
                imageloadpost();
            }
            newimages[i].onerror = function () {
                imageloadpost();
            }
        }
        return { //return blank object with done() method
            done: function (f) {
                postaction = f || postaction; //remember user defined callback functions to be called when images load
            }
        }
    }


    // print function -- associated with _print.scss
    contentToolbar.print = function () {
        $('#print-icon').on('click', function () {
            $('.leftColumn').css('height', 'auto');
            var count = 0;

            var imgArray = [];

            $('.figure-in-modal').each(function () {
                var $this = $(this);
                var imgSrc = $this.find('img');
                imgSrc.attr('src', imgSrc.attr('data-original'));
                imgArray.push(imgSrc.attr('data-original'));
            });

            contentToolbar.preloadimages(imgArray).done(function () {
                window.print();
            });
            // if no images
            if (imgArray.length == 0) window.print();
        });
    };

    // Stats logging code
    contentToolbar.LogClientActionWrapper = function (action, actionData) {
        var sectionId = $.url().param('sectionid');
        if (sectionId) {
            var intSectionId = parseInt(sectionId);
            LogClientAction(intSectionId, action, actionData);
        }
    };

    contentToolbar.statsLogging = function () {
        
        $('#print-icon').on('click', function () {
            var sectionId = $.url().param('sectionid');
            if (sectionId) {
                var intSectionId = parseInt(sectionId);
                contentToolbar.LogClientActionWrapper('print chapter', 'SectionID=' + intSectionId);
            }
        });

        $('#revealSendEmail').on('click', function () {
            contentToolbar.LogClientActionWrapper('Share', 'EmailClicked');
        });

        $('.addthis_button_facebook').on('click', function () {
            contentToolbar.LogClientActionWrapper('Share', 'FacebookClicked');
        });

        $('.addthis_button_twitter').on('click', function () {
            contentToolbar.LogClientActionWrapper('Share', 'TwitterClicked');
        });

        $('.addthis_button_linkedin').on('click', function () {
            contentToolbar.LogClientActionWrapper('Share', 'LinkedInClicked');
        });

        $('.addthis_button_citeulike').on('click', function () {
            contentToolbar.LogClientActionWrapper('Tools', 'CiteULikeClicked');
        });

        $('#PermissionsLink').on('click', function () {
            contentToolbar.LogClientActionWrapper('Tools', 'GetPermissionsClicked');
        });

        $('.articleTab').on('click', function () {
            $('#leftNavSticker').show();
            contentToolbar.LogClientActionWrapper('View', 'ArticleClicked');
        });

        $('.figureTab').on('click', function () {
            $('#leftNavSticker').hide();
            contentToolbar.LogClientActionWrapper('View', 'FiguresClicked');
        });

        $('.tableTab').on('click', function () {
            $('#leftNavSticker').hide();
            contentToolbar.LogClientActionWrapper('View', 'TablesClicked');
        });

        $('.videoTab').on('click', function () {
            $('#leftNavSticker').hide();
            contentToolbar.LogClientActionWrapper('View', 'VideosClicked');
        });

        $('.viewOriginalSlide').on('click', function () {
            var clickSectionId = $(this).attr('section');
            if (clickSectionId) {
                contentToolbar.LogClientActionWrapper('popUpFigure', 'sectionid=' + clickSectionId);
            }
        });

        $('.downloadSlide').on('click', function () {
            var clickSectionId = $(this).attr('section');
            if (clickSectionId) {
                contentToolbar.LogClientActionWrapper('DownloadSlide', 'sectionid=' + clickSectionId);
            }
        });
    };

    contentToolbar.filter();
    contentToolbar.print();
    contentToolbar.statsLogging();
});