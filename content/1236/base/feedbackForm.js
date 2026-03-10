function getRadioButtonValue(elementName) {
    var elementValue = '';
    var elementList = $('[id^=' + elementName + ']');  // get element starting with the element name to allow control name to change depending on it's location
    for (var i = 0; i < elementList.length; i++) {
        if (elementList[i].checked == true) {
            elementValue = elementList[i].value;
            break;
        }
    }
    return elementValue;
}

function initializeFeedbackFormModal() {
    // Show form only if logged in;  otherwise prompt to login
    if (document.getElementById('isLoggedIn').value === 'true') {
        $('#feedbackFormInput').show();
        $('#feedbackFormSuccess, #feedbackFormError, #notLoggedIn').hide();
    } else {
        $('#feedbackFormInput, #feedbackFormSuccess, #feedbackFormError').hide();
        $('#notLoggedIn').show();
    }
}

function sizeModalAppropriately() {
    if (document.getElementById('isLoggedIn').value === 'false' && $(window).width() > 1023) {
        $('#feedbackFormModal').removeClass('medium').addClass('tiny');
    } else {
        $('#feedbackFormModal').removeClass('tiny').addClass('medium');
    }
}



$(document).ready(function () {
    $(window).on('load', function () {
        initializeFeedbackFormModal();
        sizeModalAppropriately();

        $('#feedbackFormSubmit').on('click', function (e) {
            e.preventDefault();

            var rating = getRadioButtonValue('rblRating');

            var foundInfo = getRadioButtonValue('rblDidYouFind');

            var mayWeContactYou = getRadioButtonValue('rblMayWeContact');

            var pleaseExplainText = document.getElementById('tbPleaseExplain').value;
            var contentToAdd = document.getElementById('tbWhatContent').value;
            var firstName = document.getElementById('firstName').value;
            var lastName = document.getElementById('lastName').value;
            var emailAddress = document.getElementById('emailAddress').value;
            var param = "{'rating' : '" + rating + "','foundInfo' : '" + foundInfo + "','mayWeContactYou' : '" + mayWeContactYou + "','pleaseExplainText' : '" + pleaseExplainText
                         + "','contentToAdd' : '" + contentToAdd + "','firstName' : '" + firstName + "','lastName' : '" + lastName + "','emailAddress' : '" + emailAddress + "'}";

            $.ajax({
                type: "POST",
                url: "/Services/FeedbackFormService.asmx/SubmitFeedbackForm",
                data: param,
                dataType: "json",
                contentType: "application/json; charset=utf-8",
                success: function (msg) {
                    if (msg.d == 'Success') {
                        $('#feedbackFormInput').hide();
                        $('#feedbackFormSuccess').show();
                    } else {
                        $('#feedbackFormInput').hide();
                        $('#feedbackFormError').show();
                    }
                },
                error: function (XMLHttpRequest, textStatus, errorThrown) {
                    $('#feedbackFormInput').hide();
                    $('#feedbackFormError').show();
                }
            });
        });

        $('#close-feedback-form').on('click', function (e) {
            initializeFeedbackFormModal();
            /* if you are signed in on the signin.aspx page, then redirect to the index.aspx page */
            if (document.getElementById('isLoggedIn').value === 'true') {
                var currentLocation = document.location.href;
                if (currentLocation.indexOf("signin.aspx") > 0) {
                    currentLocation = currentLocation.replace("signin", "index");
                    document.location.href = currentLocation;
                }
            }
            $('#closeRevealModal').click();
        });
    });
    $(window).on("redraw", function () { sizeModalAppropriately(); });
    $(window).on("resize", function () { sizeModalAppropriately(); });
});



$(function () {
    $('#pleaseExplainCharRemaining').text(getCharsRemaining($('#tbPleaseExplain'), 1000));
    $('#tbPleaseExplain').keyup(function () {
        $('#pleaseExplainCharRemaining').text(getCharsRemaining($('#tbPleaseExplain'), 1000));
    });
    $('#whatContentCharRemaining').text(getCharsRemaining($('#tbWhatContent'), 1000));
    $('#tbWhatContent').keyup(function () {
        $('#whatContentCharRemaining').text(getCharsRemaining($('#tbWhatContent'), 1000));
    });
});

function getCharsRemaining(target, limit) {
    var len = $(target).val().length;
    if (len > limit) {
        $(target).val($(target).val().substring(0, limit));
        return limit;
    }
    else return (limit - len).toString();
}
