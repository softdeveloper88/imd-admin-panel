//
// Globally move reveal modals to the end of the body -- Foundation Reveal Modals don't work nested in the DOM
//
$(function() {
    $(document).foundation();

    // initialize PDF module from scm.sharedcontrols.pdfaccess.js
    SCM.PDFAccess.init();
});

function triggerLazyLoad() {
    //$("img.contentFigures").lazyload({
    //    skip_invisible: false
    //});
    $("img.inlineGraphics").lazyload({
        skip_invisible: false
    });
    $("img.lazy").lazyload({
        skip_invisible: false
    });
}
triggerLazyLoad();


// Adding contains Sting function
if (!('contains' in String.prototype)) {
    String.prototype.contains = function (str, startIndex) {
        return ''.indexOf.call(this, str, startIndex) !== -1;
    };
}

$(window).on('load', function() {
    $('.updateExpandLink').on('click', function (e) {
        e.preventDefault();
        var $this = $(this);
        $this.parents('.boxedSection').find('.abstract-section').remove();
        $this.addClass('hide').parents('.boxedSection').find('.expanded-section').removeClass('hide');
    });
});

// documentation - Lazy Load
// skip_invisible :
// Webkit browsers will report images with without width and height as not .not(":visible"). 
// This causes images to appear only when you scroll a bit. Either fix your image tags or set skip_invisible to false.

//$(document).ajaxComplete(function () {
//    $('.reveal-modal').each(function () {
//        $(this).appendTo($('body'));
//    });
//});

//$(window).load(function () {
//    $('.reveal-modal').each(function () {
//        $(this).appendTo($('body'));
//    });
//});


//$(document).ready(function () {
//    SwitchSigninValidation("PageContent");
//});


//$('#UserInfoDropdown').on('opened.fndtn.dropdown', function () {
//    SwitchSigninValidation("masthead");
//});

//$('#UserInfoDropdown').on('closed.fndtn.dropdown', function () {
//    SwitchSigninValidation("PageContent");
//});



//$('#feedbackFormModal').on('opened.fndtn.reveal', function () {
//    SwitchSigninValidation("siteFooter");
//});

//$('#feedbackFormModal').on('closed.fndtn.reveal', function () {
//    SwitchSigninValidation("PageContent");
//});

//function SwitchSigninValidation(controlContains) {
//    if ($("#pnlGlobalSignin").length > 0) {
//        var i;
//        for (i = 0; i < Page_Validators.length; i++) {
//            if (Page_Validators[i].controltovalidate.indexOf(controlContains) != -1) {
//                ControlValidatorEnable(Page_Validators[i], true);
//            } else {
//                ControlValidatorEnable(Page_Validators[i], false);
//            }
//        }
//    }
//}

//function ControlValidatorEnable(control, enable) {
//    if (control) {
//        ValidatorEnable(control, enable);
//        if (control.style.visibility == "visible") {
//            control.style.visibility = "hidden";
//        } else {
//            control.style.display = "none";
//        }
//    }
//}
