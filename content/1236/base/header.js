/*
 * jQuery outside events - v1.1 - 3/16/2010
 * http://benalman.com/projects/jquery-outside-events-plugin/
 * 
 * Copyright (c) 2010 "Cowboy" Ben Alman
 * Dual licensed under the MIT and GPL licenses.
 * http://benalman.com/about/license/
 */
(function ($, c, b) { $.map("click dblclick mousemove mousedown mouseup mouseover mouseout change select submit keydown keypress keyup".split(" "), function (d) { a(d) }); a("focusin", "focus" + b); a("focusout", "blur" + b); $.addOutsideEvent = a; function a(g, e) { e = e || g + b; var d = $(), h = g + "." + e + "-special-event"; $.event.special[e] = { setup: function () { d = d.add(this); if (d.length === 1) { $(c).bind(h, f) } }, teardown: function () { d = d.not(this); if (d.length === 0) { $(c).unbind(h) } }, add: function (i) { var j = i.handler; i.handler = function (l, k) { l.target = k; j.apply(this, arguments) } } }; function f(i) { $(d).each(function () { var j = $(this); if (this !== i.target && !j.has(i.target).length) { j.triggerHandler(e, [i.target]) } }) } } })(jQuery, document, "outside");

/*Brand Section - Header Menu Navigation*/
/*Author: Subash Maharjan*/
/*For Documentation: 
    Account, Search and Microsite logo toggling functionality
*/

document.createElement('header');
document.createElement('nav');
document.createElement('menu');
document.createElement('section');
document.createElement('article');
document.createElement('aside');
document.createElement('footer');

$(document).ready(function () {
    $(document).foundation('topbar', 'off');

    //Handles Global Sign In Toggle
    $('[data-toggle-target=#signInDropdown]').on('click', function () {
        var $target = $($(this).attr('data-toggle-target'));
        $target.toggleClass('expanded');
        $(this).toggleClass('active');
        if ($(this).hasClass('active')) SwitchSigninValidation("masthead");
        else SwitchSigninValidation("PageContent");
    });
    //Hide the Global Sign In when someone clicks outside of it.
    $("#userInfo").on("clickoutside", function (event) {
        if ($('[data-toggle-target=#signInDropdown]').hasClass('active')) {
            SwitchSigninValidation("PageContent");
            $('#signInDropdown').removeClass('expanded');
            $('[data-toggle-target=#signInDropdown]').removeClass('active');
        }
    });

    //Open Sign Dropdown if returning to the page after failed login attempt, otherwise default validation context to page sign in
    if (typeof GlobalSignin !== "undefined" && GlobalSignin.status === 'failed') {
        $('[data-toggle-target=#signInDropdown]').trigger('click');
    } else SwitchSigninValidation("PageContent");

    $('#feedbackFormModal').on('opened.fndtn.reveal', function () {
        SwitchSigninValidation("siteFooter");
    });

    $('#feedbackFormModal').on('closed.fndtn.reveal', function () {
        SwitchSigninValidation("PageContent");
    });

    if ($("#keepMeOpen").attr("value") == 'true') {
        $("#openFeedbackForm").trigger('click');
        $("#keepMeOpen").attr("value", 'false');
    }

    function SwitchSigninValidation(controlContains) {
        if ($("#pnlGlobalSignin").length > 0) {
            var i;
            for (i = 0; i < Page_Validators.length; i++) {
                if (Page_Validators[i].controltovalidate && Page_Validators[i].controltovalidate.indexOf(controlContains) != -1) {
                    ControlValidatorEnable(Page_Validators[i], true);
                } else {
                    ControlValidatorEnable(Page_Validators[i], false);
                }
            }
        }
    }

    function ControlValidatorEnable(control, enable) {
        if (control) {
            ValidatorEnable(control, enable);
            if (control.style.visibility == "visible") {
                control.style.visibility = "hidden";
            } else {
                control.style.display = "none";
            }
        }
    }

    //If No Microsites, hide dropdown icon
    if ($('#micrositeMenuSectionMobile').length == 0) $('.headerBottomPortion section.middle i').remove();

    $('.headerBottomPortion').find('.menu-toggle').on('click', function (e) {
        var $this = $(this);
        var $target = $($this.attr('data-target'));
        if (($(window).width() < 1025) && $target.length !== 0) {
            $('.headerBottomPortion .tab-bar .expanded, #healthLibrarySearch').not($target).removeClass('expanded');
            $target.toggleClass('expanded');
            $this.toggleClass('active');
            $('.headerBottomPortion .menu-toggle').not($this).removeClass('active');
            e.stopPropagation();
            return false;
        };
    });

    function menuToggle($this, e) {
        var $title = $this.find('h1').text();
        var child = "#" + $this.find('ul').attr('id');
        if (($(window).width() > 1024) || $('html').hasClass('lt-ie9')) {
            if (child == '#micrositeMenuSection') {
                if ($title.toUpperCase() == 'CLERKSHIP/CLINICAL ROTATIONS') {
                    $this.toggleClass('active');
                    $this.closest('section').toggleClass('clerkship-active');
                } else {
                    $this.closest('section').toggleClass('active');
                }

            } else if (child == '#rotationDropdownMenu') {
                $this.toggleClass('active');
            }
            if ($(child).length) {
                $(child).toggleClass('expanded');
            }
            e.stopPropagation();
            return false;
        }
    }

    $('.headerBottomPortion .menu-toggle').on("mouseenter", function (e) {
        menuToggle($(this), e);
    }).on("mouseleave", function (e) {
        menuToggle($(this), e);
    });


    var switched = false;
    var updateHomeLayout = function () {


        //meded title overlapping texts
        //https://jira.silverchair.com/browse/WKHL-241

        var $tabBarSection = $('.tab-bar-section').removeAttr('style');
        var $mobileMainMenuHeader = $tabBarSection.find('.menu-toggle').find('h1');
        
        if (Modernizr.mq('only all and (max-width: 1024px)')) {
               
            $tabBarSection.css('width', $tabBarSection.width() + 1);

            var fontSize = 500, $siteId = $('#hdnSiteID').attr('value'), $winW = $(window).width();

            // Responsive Fit-Text for headers
            if ($siteId == '138') fontSize = 101;   // Airway Management
            if ($siteId == '153') fontSize = 98;    // Orthopaedic Surgery
            if ($siteId == '165') fontSize = 93;    // Occupational Therapy
            if ($siteId == '167') fontSize = 78;    // Speech, Language, Hearing

            // Clerkship/Clinical Rotations
            if ($siteId == '190') {
                if (Modernizr.mq('only all and (max-width: 640px)')) {
                    fontSize = 72;    // Clerkship/Clinical Rotations
                } else {
                    fontSize = 48;
                }
            }
                
            fontSize = (fontSize / 320) * $winW;

            if (fontSize < 181) $mobileMainMenuHeader.css('font-size', fontSize + '%');

            //$tabBarSection.append($('#rotationDropdownMenu'));

        }  else if (Modernizr.mq('only all and (min-width: 1025px)')) {
            
            $mobileMainMenuHeader.removeAttr('style');

            $('.menu-toggle').removeClass('active');
            $('.tab-bar').find('.expanded').removeClass('expanded');

            var $leftSmall = $('.left-small').removeAttr('style');
            var $navBar = $('.tab-bar').width();
            var $mainMenuSection = $('#mainMenuSection').width();
            var rotationMenuExists = $('#dvRotationMenu').length ? true : false;
            var diff = $navBar - $mainMenuSection;

            
            if ($leftSmall.width() > diff) {

                var a = 2;
                if (!rotationMenuExists) {
                    if (diff > 100 && diff < 200) {
                        a = 3.5;
                    } else if (diff > 200 && diff < 300) {
                        a = 3;
                    } else if (diff > 300 && diff < 400) {
                        a = 2.5;
                    }
                } else {
                    a = 0.5;
                }
                $leftSmall.find('h1').css('font-size', (diff / $mainMenuSection) * (a * 95) + '%');
            }
            
            //$leftSmall.append($('#rotationDropdownMenu'));
        }
    };

    $(window).load(function () {
        //set navigation active state
        var url = window.location.pathname,
        urlRegExp = new RegExp(url.replace(/\/$/, '') + "$");

        if (url === '/') {
            $('#menuSection').first().addClass('active');
        } else {
            $('#menuSection a').each(function () {
                // and test its normalized href against the url pathname regexp
                if (urlRegExp.test(this.href.replace(/\/$/, ''))) {
                    $(this).closest('#menuSection').addClass('currentPage');
                }
            });
        }
        updateHomeLayout();

        $('.rotation-menu li.active').on('click', function () {
            $(this).siblings().toggle();
        });
    });

    $(window).on("redraw", function () { switched = false; updateHomeLayout(); }); // An event to listen for
    $(window).on("resize", function () { updateHomeLayout(); });
});
$(document).on('opened', '[data-reveal="feedbackFormModal"]', function () {
    var modal = $(this);
    modal.appendTo('form');
});
