//TODO: none of this should be in the global namespace, should refactor

var sectionsLogged = [];
var fakeMutex = false;
var inScroll = false;
var inScrollSectionId = true;
var urlParams = {};
var sectionLogIntevalTimer = null;

(function ($) {

    /**
	 * Copyright 2012, Digital Fusion
	 * Licensed under the MIT license.
	 * http://teamdf.com/jquery-plugins/license/
	 *
	 * @author Sam Sehnert
	 * @desc A small plugin that checks whether elements are within
	 *		 the user visible viewport of a web browser.
	 *		 only accounts for vertical position, not horizontal.
	 */
    $.fn.visible = function (partial) {

        var $t = $(this),
	    	$w = $(window),
	    	viewTop = $w.scrollTop(),
	    	viewBottom = viewTop + $w.height(),
	    	_top = $t.offset().top,
	    	_bottom = _top + $t.height(),
	    	compareTop = partial === true ? _bottom : _top,
	    	compareBottom = partial === true ? _top : _bottom;

        return ((compareBottom <= viewBottom) && (compareTop >= viewTop));
    };

})(jQuery);

var Scheduler = (function () {
    var tasks = [];
    var minimum = 10;
    var timeoutVar = null;
    var output = {
        add: function (func, context, timer, once) {
            var iTimer = parseInt(timer);
            context = context && typeof context === 'object' ? context : null;
            if (typeof func === 'function' && !isNaN(iTimer) && iTimer > 0) {
                tasks.push([func, context, iTimer, iTimer * minimum, once]);
            }
        },
        remove: function (func, context) {
            for (var i = 0, l = tasks.length; i < l; i++) {
                if (tasks[i][0] === func && (tasks[i][1] === context || tasks[i][1] == null)) {
                    tasks.splice(i, 1);
                    return;
                }
            }
        },
        halt: function () {
            if (timeoutVar) {
                clearInterval(timeoutVar);
            }
        }
    };
    var schedule = function () {
        for (var i = 0, l = tasks.length; i < l; i++) {
            if (tasks[i] instanceof Array) {
                tasks[i][3] -= minimum;
                if (tasks[i][3] < 0) {
                    tasks[i][3] = tasks[i][2] * minimum;
                    tasks[i][0].apply(tasks[i][1]);
                    if (tasks[i][4]) {
                        tasks.splice(i, 1);
                    }
                }
            }
        }
    };
    timeoutVar = setInterval(schedule, minimum);
    return output;
})();

(function () {
    // Your base, I'm in it!
    var originalAddClassMethod = jQuery.fn.addClass;
    var lastPromise = $.Deferred().resolve().promise();
    jQuery.fn.addClass = function () {
        // Execute the original method.
        var result = originalAddClassMethod.apply(this, arguments);

        if ((arguments.length > 0) && (arguments[0] == "active")) {
            var sectionId = $(this).attr("data-magellan-arrival");

            if (sectionId) {
                var intSectionId = parseInt(sectionId);

                if (!inScroll) {
                    Scheduler.add(function () {
                        if (window.console) console.log('--');
                        // re-fetch to make sure it isn't a cached object
                        var item = $("[data-magellan-arrival='" + sectionId + "']");
                        if (item && item.hasClass('active')) {
                            lastPromise = lastPromise.done(LogSectionAccess(intSectionId));
                        }
                    }, null, 500, true);
                } else {
                    if (intSectionId == inScrollSectionId) { // this means that the scrolling has reached the desired section.
                        inScroll = false;
                    }
                }
            }
        }

        // return the original result
        return result;
    };
})();

$(document).ready(function () {
    (window.onpopstate = function () {
        var match,
            pl = /\+/g,  // Regex for replacing addition symbol with a space
            search = /([^&=]+)=?([^&]*)/g,
            decode = function (s) { return decodeURIComponent(s.replace(pl, " ")); },
            query = window.location.search.substring(1);

        urlParams = {};
        while (match = search.exec(query))
            urlParams[decode(match[1])] = decode(match[2]);
    })();

    $('.widget-RelatedPubMed .article-title a').click(function () {
        var sectionId = urlParams["sectionid"];

        if (sectionId) {
            LogClientAction(sectionId, 'RelatedPubMedWidget', $(this).attr('href'));
        }
    });
    
    $('.widget-RelatedPubMed .view-more a').click(function () {
        var sectionId = urlParams["sectionid"];

        if (sectionId) {
            LogClientAction(sectionId, 'RelatedPubMedWidget', 'All Results Clicked');
        }
    });

    $('.section-jump-link').click(function () {
        inScroll = true;  // this will be true until the section is reached by the "scrolling" activated by Magellan.
        var sectionId = $(this).attr("data-magellan-arrival");

        if (sectionId) {
            var intSectionId = parseInt(sectionId);
            inScrollSectionId = intSectionId;
            LogSectionAccess(intSectionId);
        }
    });

    // report an expansion on the first section

    var element = $('.section-jump-link').first();

    if (element) {
        var sectionId = element.attr("data-magellan-arrival");

        if (sectionId) {
            var intSectionId = parseInt(sectionId);
            LogSectionAccess(intSectionId);
        }
    }

    // Setup a interval to check for viewed, but unlogged sections

    sectionLogIntevalTimer = setInterval(CheckForViewedButUnloggedSections, 1000);

    $('.tablelink, .caption-title, .icon-table, .figLink').click(function () {
        // only span tags for tables that aren't in the modal popups should be processed.
        if ($(this).prop('tagName') == 'SPAN' && !($(this).parents('.table-section').size() > 0 && $(this).parents('#revealContent').size() == 0)) {
            return;
        }
        var sectionId = 0;
        var statsParent = $(this).closest("div[statsid]");

        if (statsParent) {
            sectionId = parseInt(statsParent.attr("statsid"));
        }

        
        var popupType = ($(this).parents('.table-section').size() > 0) ? 4140 : 4145;


        if (sectionId) {

            var dataValue = '{ "sectionId": "' + sectionId + '", "popUpType" : "' + popupType + '" }';

            $.ajax({
                type: "POST",
                url: "Content.aspx/ReportPopupAccess",
                contentType: 'application/json; charset=utf-8',
                data: dataValue,
                error: function (xmlHttpRequest, textStatus, errorThrown) {

                },
                success: function (jqXhr, status) {

                }
            });
        }
    });
});

function CheckForViewedButUnloggedSections() {

    $("[data-magellan-destination]").each(function() {
        
        var sectionId = $(this).attr("data-magellan-destination");

        if (sectionId) {

            var intSectionId = parseInt(sectionId);

            var alreadyLogged = false;

            for (var j = 0; j < sectionsLogged.length; j++) {
                if (sectionsLogged[j] === intSectionId) {
                    alreadyLogged = true;
                    break;
                }
            }

            // if the section is visible, but haven't logged it, do so

            if (!alreadyLogged && $(this).visible(true)) {
                LogSectionAccess(intSectionId);
            }

        }
    });
}

function LogSectionAccess(sectionId) {

    var alreadyLogged = false;

    for (var i = 0; i < sectionsLogged.length; i++) {
        if (sectionsLogged[i] === sectionId) {
            alreadyLogged = true;
            break;
        }
    }

    if (!alreadyLogged) {
        var dataValue = '{ "sectionId": ' + sectionId + ' }';
        sectionsLogged.push(sectionId);

        return $.ajax({
            type: "POST",
            url: "Content.aspx/ReportSectionAccess",
            contentType: 'application/json; charset=utf-8',
            data: dataValue,
            error: function (xmlHttpRequest, textStatus, errorThrown) {
                //alert("Request: " + xmlHttpRequest.toString() + "\n\nStatus: " + textStatus + "\n\nError: " + errorThrown);
            },
            success: function (jqXhr, status) {
                //console.log("logged section:" + sectionId);
            }
        });
    } else {
        var def = $.Deferred();
        def.resolve();
        return def.promise();
    }
}


function LogClientAction(sectionId, action, actionData) {

    if (!fakeMutex) {
        fakeMutex = true;

        var dataValue = '{ "sectionId": ' + sectionId + ', "action": "' + action + '", "actionData": "' + actionData + '" }';
        $.ajax({
            type: "POST",
            url: "Content.aspx/ReportClientAction?sectionid=" + sectionId,
            contentType: 'application/json; charset=utf-8',
            data: dataValue,
            error: function (xmlHttpRequest, textStatus, errorThrown) {
                //alert("Request: " + xmlHttpRequest.toString() + "\n\nStatus: " + textStatus + "\n\nError: " + errorThrown);
                fakeMutex = false;
            },
            success: function (jqXhr, status) {
                fakeMutex = false;
            }
        });
    }
}
