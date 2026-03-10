$(document).ready(function () {

    function chooseAccount(isNewUser) {
        if (isNewUser) {
            document.getElementById('rbNewUser').checked = true;
            document.getElementById('txtOldEmail').value = '';
            document.getElementById('txtOldPassword').value = '';
        } else {
            document.getElementById('rbOldUser').checked = true;
            document.getElementById('txtNewEmail').value = '';
        }
    }

    function accessCodeReturnPress(e, accessCode) {
        var code = e.keyCode;
        if (code == 13) {
            e.preventDefault();
            checkAccessCode(accessCode);
            return false;
        }
        return true;
    }

    function checkAccessCode(accessCode) {
        var param = "{'accessCode' : '" + accessCode + "'}";

        $.ajax({
            type: "POST",
            url: "/Services/AccessCodeService.asmx/ValidateAccessCode",
            data: param,
            dataType: "json",
            contentType: "application/json; charset=utf-8",
            success: function (msg) {
                if (msg.d.IsValid && msg.d.IsValid == "True") {
                    window.location.href = "/account/hlStore.aspx?accessCode=" + encodeURIComponent(accessCode) + "&retUrl=" + encodeURIComponent(window.location.href);
                } else {
                    $('.access-code-invalid').text(msg.d.ValidationMessage);
                    $('.access-code-invalid').show();
                }
            },
            error: function (XMLHttpRequest, textStatus, errorThrown) {
                $('#accessCodeError').show();
                $('#accessCodeErrorMessage').show();
            }
        });
    }

    $(window).on('load', function () {
        $('#accessCodeInvalid, #accessCodeError').hide();
        $('#accessCodeInvalidMessage, #accessCodeErrorMessage').hide();

        $('#close-access-code-form').on('click', function (e) {
            $('#closeRevealModal').click();
        });

        $("#tbAccessCode").on("keyup", function (e) {
            return accessCodeReturnPress(e, $('#tbAccessCode').val());
        });
        $("#tbCCAccessCode").on("keyup", function (e) {
            return accessCodeReturnPress(e, $('#tbCCAccessCode').val());
        });


        $('#accessCodeFormSubmit').on('click', function () {
            checkAccessCode($('#tbAccessCode').val());
        });
        $('#accessCodeFormSubmitHome').on('click', function () {
            checkAccessCode($('#tbAccessCodeHome').val());
        });


        $('#redeemAccessCodeSubmit').on('click', function () {
            checkAccessCode($('#tbCCAccessCode').val());
        });
    });
});


