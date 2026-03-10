/*global*/
function init()
{
    /* deprecated: the buildToc() and registerBackToTop() calls will now be called by the sg one theme as needed */
}

function registerBackToTop() {
    var backToTop = document.getElementById("back-to-top");

    console.log("registerBackToTop()");

    if (!backToTop) {
        // create it and append it to body
        backToTop = document.createElement("a");
        backToTop.id = "back-to-top";
        backToTop.href = "javascript:window.scrollTo(0,0);";

        document.body.appendChild(backToTop);

        backToTop.style.position = "fixed";
        backToTop.height = "50px";
        backToTop.width = "75px";
        backToTop.style.bottom = "0px";
        backToTop.innerHTML = "Top";
    }


    //Start listening for scroll events: this is necessary to pick up on minute scroll events on mobile devices (onScroll is not sensitive enough)
    setInterval("backToTop_onScroll()", 100);
}

function backToTop_onScroll() {
    // if the scroll top is more than the height of the viewport, then show back to top
    var scrollTop = $(document).scrollTop();
    //var viewportHeight = Math.max(document.documentElement.clientHeight, window.innerHeight || 0);
    var viewportHeight = $(window).height();
    atTop = scrollTop <= viewportHeight;

    console.log("scrollTop=" + scrollTop + "; viewportHeight=" + viewportHeight + "; atTop=" + atTop);

    if (!atTop) {
        showBackToTop();
    } else {
        hideBackToTop();
    }
}

function showBackToTop() {
    var backToTop = document.getElementById("back-to-top");

    backToTop.style.visibility = "visible";
    backToTop.display = "block";
}

function hideBackToTop() {
    var backToTop = document.getElementById("back-to-top");

    backToTop.style.visibility = "hidden";
    backToTop.display = "none";
}

String.prototype.replaceAll = function (find, replace) {
    return this.replace(new RegExp(find, 'g'), replace);
}

/* Drug Information pages */
function setFocus(elem) {
    if (elem) {
        elem.tabIndex = -1;
        try {
            // focus by moving scrollTop
            var x = 0;
            var y = 0;
            while (elem != null) {
                x += elem.offsetLeft;
                y += elem.offsetTop;
                elem = elem.offsetParent;
            }
            window.scrollTo(x, y);
        } catch (e) {
            //alert(" error occurred in setting focus");
            elem.focus();
        }
    }
}

function jumpTo(id) {
    var elem = document.getElementById(id);
    if (elem) {
        elem.tabIndex = -1;
        elem.focus();
    }
}

function jumpToElementById(id) {
    var elem = document.getElementById(id);

    if (!elem) {
        elem = document.getElementById(id);
    }
    if (elem) {
        setFocus(elem);
    }
}

/* End Drug Information pages */
// Table of Contents
function jumpToTocItem() {
    var toc = document.getElementById("cboToc");

    if (toc) {
        var elemId = toc.options[toc.selectedIndex].value;

        jumpToElementById(elemId);
    }
}
function buildToc() {
    //var h3Lst = document.getElementsByTagName("h3");
    var h3Lst = new Array();
    var cboToc = document.createElement("select");
    cboToc.id = "cboToc";
    var all = document.getElementsByTagName("*");

    // Add h2 and h3 tags to the heading list
    for (var i = 0; i < all.length; i++) {
        var e = all[i];
        if (e.tagName && (e.tagName.toUpperCase() == "H2" || e.tagName.toUpperCase() == "H3")) {
            h3Lst[h3Lst.length] = e;
        }
    }

    // for each h3 tag, add a tocId to it
    for (var i = 0; i < h3Lst.length; i++) {
        var h3 = h3Lst[i];
        var newOpt = document.createElement("option");

        h3.id = "toc_" + i;

        newOpt.text = h3.innerText;
        newOpt.value = "toc_" + i;

        cboToc.add(newOpt, null);
    }

    // if there is a valid table of contents, then add it to the DOM
    if (cboToc.options.length > 0) {
        cboToc.onchange = jumpToTocItem;
        document.body.insertBefore(cboToc, document.getElementById("mobile-container-div"));
    }

}

var uiWebview_SearchResultCount = 0;

function uiWebview_HighlightAllOccurencesOfStringForElement(element, keyword) {

    if (element) {
        if (element.nodeType == 3) {        // Text node
            while (true) {
                //if (counter < 1) {
                var value = element.nodeValue;  // Search for keyword in text node
                var idx = value.toLowerCase().indexOf(keyword);

                if (idx < 0)
                    break;             // not found, abort

                //(value.split);

                //we create a <highlight> element for every parts of matched keywords
                var highlight = document.createElement("highlight");
                var text = document.createTextNode(value.substr(idx, keyword.length));
                highlight.appendChild(text);

                highlight.setAttribute("class", "uiWebviewHighlight");
                highlight.style.backgroundColor = "yellow";
                highlight.style.color = "black";

                uiWebview_SearchResultCount++;    // update the counter

                text = document.createTextNode(value.substr(idx + keyword.length));
                element.deleteData(idx, value.length - idx);
                var next = element.nextSibling;
                element.parentNode.insertBefore(highlight, next);
                element.parentNode.insertBefore(text, next);
                element = text;

                // Tyler 6/30/22: removing automatic page scroll after search term highlighting as it is causing jank in app and causing ios content page
                // headers to truncate their text as if the user scrolled the page down during initial page load. Making the header unreadable
                // window.scrollTo(0, highlight.offsetTop);

            }
        } else if (element.nodeType == 1) { // Element node
            if (element.style.display != "none" && element.nodeName.toLowerCase() != 'select') {
                for (var i = element.childNodes.length - 1; i >= 0; i--) {
                    uiWebview_HighlightAllOccurencesOfStringForElement(element.childNodes[i], keyword);
                }
            }
        }
    }
}

// the main entry point to start the search
function uiWebview_HighlightAllOccurencesOfString(keyword) {
    //uiWebview_RemoveAllHighlights();
    uiWebview_HighlightAllOccurencesOfStringForElement(document.body, keyword.toLowerCase());
}

// helper function, recursively removes the highlights in elements and their childs
function uiWebview_RemoveAllHighlightsForElement(element) {
    if (element) {
        if (element.nodeType == 1) {
            if (element.getAttribute("class") == "uiWebviewHighlight") {
                var text = element.removeChild(element.firstChild);
                element.parentNode.insertBefore(text, element);
                element.parentNode.removeChild(element);
                return true;
            } else {
                var normalize = false;
                for (var i = element.childNodes.length - 1; i >= 0; i--) {
                    if (uiWebview_RemoveAllHighlightsForElement(element.childNodes[i])) {
                        normalize = true;
                    }
                }
                if (normalize) {
                    element.normalize();
                }
            }
        }
    }
    return false;
}
// the main entry point to remove the highlights
function uiWebview_RemoveAllHighlights() {
    uiWebview_SearchResultCount = 0;
    uiWebview_RemoveAllHighlightsForElement(document.body);
}


/*
 * jQuery Asynchronous Plugin 1.0 RC1
 *
 * Copyright (c) 2008 Vincent Robert (genezys.net)
 * Dual licensed under the MIT (MIT-LICENSE.txt)
 * and GPL (GPL-LICENSE.txt) licenses.
 *
 */
(function ($) {

// opts.delay : (default 10) delay between async call in ms
// opts.bulk : (default 500) delay during which the loop can continue synchronously without yielding the CPU
// opts.test : (default true) function to test in the while test part
// opts.loop : (default empty) function to call in the while loop part
// opts.end : (default empty) function to call at the end of the while loop
    $.whileAsync = function (opts)
    {
        var delay = Math.abs(opts.delay) || 10,
                bulk = isNaN(opts.bulk) ? 500 : Math.abs(opts.bulk),
                test = opts.test || function () {
                    return true;
                },
                loop = opts.loop || function () {},
                end = opts.end || function () {};

        (function () {

            var t = false,
                    begin = new Date();

            while (t = test())
            {
                loop();
                if (bulk === 0 || (new Date() - begin) > bulk)
                {
                    break;
                }
            }
            if (t)
            {
                setTimeout(arguments.callee, delay);
            } else
            {
                end();
            }

        })();
    }

// opts.delay : (default 10) delay between async call in ms
// opts.bulk : (default 500) delay during which the loop can continue synchronously without yielding the CPU
// opts.loop : (default empty) function to call in the each loop part, signature: function(index, value) this = value
// opts.end : (default empty) function to call at the end of the each loop
    $.eachAsync = function (array, opts)
    {
        var i = 0,
                l = array.length,
                loop = opts.loop || function () {};

        $.whileAsync(
                $.extend(opts, {
                    test: function () {
                        return i < l;
                    },
                    loop: function ()
                    {
                        var val = array[i];
                        return loop.call(val, i++, val);
                    }
                })
                );
    }

    $.fn.eachAsync = function (opts)
    {
        $.eachAsync(this, opts);
        return this;
    }

})(jQuery)
