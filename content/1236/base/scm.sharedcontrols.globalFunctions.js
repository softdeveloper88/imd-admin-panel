var SCM = SCM || {};

SCM.UploadImage_Complete = function (settings) {

    var data = $.extend({
        targetSelector: '#UploadTarget',
        jsonResultSelector: '#jsonResult',
        replacementContainerSelector: '#id'
    },
        settings);

    var jsonResult = $(data.targetSelector).contents().find(data.jsonResultSelector);

    if (jsonResult.length === 1) {
        var validationResult = $.parseJSON(jsonResult.html());

        $('[data-valmsg-for]').attr('class', 'field-validation-valid').html('');
        if (validationResult.Success) {
            if (data.success) {
                data.success();
            }
        } else if (validationResult.Messages.length > 0) {
            var msg = "Error \n";
            validationResult.Messages.forEach(function (errorMsg) {
                msg += errorMsg + "\n";
            });
            alert(msg);
        } else if (validationResult.Html) {
            $(data.replacementContainerSelector).replaceWith(validationResult.Html.replace(/{{/g, '&quot;'));
        } else {
            validationResult.ValidationErrors.forEach(function (validationError) {

                var $validationSpan = $('[data-valmsg-for=' + validationError.Key + ']');
                $validationSpan.addClass('field-validation-error').removeClass('field-validation-valid');
                validationError.Errors.forEach(function (errorMsg) {
                    $validationSpan.html($validationSpan.html() + errorMsg + "<br />");
                });
            });
        }
    }
};


SCM.AjaxHelperSuccessCallback = function (data, replacementContainer, onSuccessCallback) {
    if (data.RedirectUrl &&
        data.RedirectUrl.length > 0) {
        window.location = data.RedirectUrl;
    } else if (data.Html &&
        data.Html.length > 0) {
        replacementContainer.replaceWith(data.Html);
    } else if (!data.Success) {
        replacementContainer.replaceWith(data);
    } else {
        onSuccessCallback();
    }
};


SCM.AjaxHelperErrorCallback = function (data, replacementContainer, onErrorCallback) {
    if (data.RedirectUrl &&
        data.RedirectUrl.length > 0) {
        window.location = data.RedirectUrl;
    } else if (data.Html &&
        data.Html.length > 0) {
        replacementContainer.replaceWith(data.Html);
    } else if (!data.Success) {
        replacementContainer.replaceWith(data);
    } else {
        onErrorCallback();
    }
};


SCM.showModal = function () {
    var editorIds = [];

    if (typeof tinyMCE !== 'undefined') {
        tinyMCE.editors.forEach(function (editor) {
            $('#divDefaultUpdateTarget').find('#' + editor.editorContainer).each(function () { editorIds.push(editor.id); });
        });
    }
    $.fancybox({
        'autosize': true,
        'autoScale': false,
        'title': "",
        'href': '#divDefaultUpdateTarget'
    });

    if (typeof tinyMCE !== 'undefined') {
        editorIds.forEach(function (id) { $('#' + id).scmTinyMCE(); });
    }
};


SCM.hideModal = function () {
    $.fancybox.close();
};


SCM.refreshModal = function () {
    $.fancybox.update();
};


//set up global functions
(function () {

    var $body = $('body');

    //ajax error handler
    $(document).ajaxError(function (jqXHR, ajaxSettings, thrownError) {
        $body.removeClass('wait');
        if (ajaxSettings.responseText) {
            try {
                var obj = $.parseJSON(ajaxSettings.responseText);

                if (obj.Success != null && !obj.Success) {
                    var msg = "There was an error processing the request \n";

                    obj.Messages.forEach(function (m) { msg += m + "\n"; });

                    alert(msg);
                }
            } catch (err) {
                console.log("Ajax error occured, responseText is not json: " + err.message);
                //do nothing, we do not have valid json
            }
        }
    });


    $.validator.addMethod('isDateGreaterThan', function (value, element, params) {

        if (isPastDate($(element).val(), params) == true) {
            return false;
        } else {
            return true;
        }
    }, '');


    function isPastDate(value, dateToCheck) {
        var now = new Date(dateToCheck);
        var target = new Date(value);

        if (now.getFullYear() == target.getFullYear() && now.getMonth() == target.getMonth() && now.getDate() == target.getDate()) {
            return false;
        }
        else if (now > target) {
            return true;
        }

        return false;
    }


    $('html')
       .ajaxStart(function () {
           $body.addClass('wait');
       })
       .ajaxStop(function () {
           $body.removeClass('wait');
       });

    //default button
    $body.on('keypress', '[data-default-button]', function (e) {
        if (e.which == 13) {
            $("#" + $(this).data('defaultButton')).click();
            return false;
        }
    });

    $.validator.unobtrusive.adapters.add('dynamicrange', ['minvalueproperty', 'maxvalueproperty'],
   function (options) {
       options.rules['dynamicrange'] = options.params;
       if (options.message != null) {
           $.validator.messages.dynamicrange = options.message;
       }
   }
   );

    function getModelPrefix(fieldName) {
        return fieldName.substr(0, fieldName.lastIndexOf(".") + 1);
    }

    function appendModelPrefix(value, prefix) {
        if (value.indexOf("*.") === 0) {
            value = value.replace("*.", prefix);
        }
        return value;
    }

    $.validator.addMethod('dynamicrange', function (value, element, params) {
        var prefix = getModelPrefix(element.name);

        var minValue = parseInt($('input[name="' + appendModelPrefix(params.minvalueproperty, prefix) + '"]').val(), 10);
        var maxValue = parseInt($('input[name="' + appendModelPrefix(params.maxvalueproperty, prefix) + '"]').val(), 10);

        var currentValue = parseInt(value, 10);
        if (isNaN(minValue) || isNaN(maxValue) || isNaN(currentValue) || minValue > currentValue || currentValue > maxValue) {
            $.validator.messages.dynamicrange = $.format($(element).attr('data-val-dynamicrange'), minValue, maxValue);
            return false;
        }
        return true;
    }, '');

})();


//plugins
(function ($) {

    $.fn.radiobuttonEnable = function () {
        return this.each(function () {
            var $container = $(this);
            $container.find('*[data-rb-enable-name]').each(function () {
                var $element = $(this);
                var $rb = $container.find('input:radio[name="' + $element.data('rbEnableName') + '"]:checked');
                if ($rb.length > 0) {
                    var data = $element.data('rbEnableValue');
                    if (data != null &&
                        $rb.val().toString().toLowerCase() != data.toString().toLowerCase()) {
                        $element.attr('disabled', 'disabled');
                    }

                    data = $element.data('rbMakeVisibleValue');
                    if (data != null &&
                        $rb.val().toString().toLowerCase() != data.toString().toLowerCase()) {
                        $element.hide();
                    }
                }
            });

            $container.find('input:radio').on('change', function () {
                var $rb = $(this);
                var selector = '[data-rb-enable-name="' + $rb.attr('name') + '"]';
                var $inputs = $(selector);

                $inputs.each(function () {
                    var $element = $(this);

                    var tinyEditor = tinymce.editors[$element[0].id];
                    var data = $element.data('rbEnableValue');
                    if (data != null) {
                        if (data.toString().toLowerCase() == $rb.val().toLowerCase()) {
                            $element.removeAttr('disabled');
                            if (tinyEditor) {
                                tinyEditor.getBody().setAttribute('contenteditable', true);
                            }
                        } else {
                            $element.attr('disabled', 'disabled');
                            if (tinyEditor) {
                                tinyEditor.getBody().setAttribute('contenteditable', false);
                            }
                        }
                    }

                    data = $element.data('rbMakeVisibleValue');
                    if (data != null) {
                        if ((data.toString().toLowerCase() == $rb.val().toLowerCase() && !$element.is(':visible')) ||
                            (data.toString().toLowerCase() != $rb.val().toLowerCase() && $element.is(':visible'))) {
                            $element.fadeToggle();
                        }
                    }
                });

            });
        });
    };

    $.fn.configureSCMForm = function (data) {

        var settings = $.extend({
            cancelButtonSelector: '.cancel',
            submitButtonSelector: '.submit',
            nextQuestionButtonSelector: '.nextQuestion',
            skipButtonSelector: '.skip',
            validatorIgnores: ":disabled, input[type='hidden']",
            nextQuestion: null,
            cancel: null,
            skip: null,
            validateOnSubmit: null,
            validateOnKeyUp: false

        }, data);

        return this.each(function () {

            var $form = $(this);

            jQuery.validator.unobtrusive.parse('#' + this.id);
            $form.validate();
            var validatorSettings = $.data($form[0], 'validator').settings;
            validatorSettings.ignore = settings.validatorIgnores;
            if (settings.validateOnKeyUp === true) {
                settings.validateOnKeyUp = null;
            }
            validatorSettings.onkeyup = settings.validateOnKeyUp;
            validatorSettings.onsubmit = settings.validateOnSubmit;
            $form.find(settings.submitButtonSelector)
                .off('click.configureSCMForm')
                .on('click.configureSCMForm', function (e) {
                    e.preventDefault();
                    if ($form.valid()) {
                        $form.trigger('submit');
                    }
                });

            $form.find(settings.nextQuestionButtonSelector)
               .off('click.configureSCMForm')
               .on('click.configureSCMForm', function (e) {
                   e.preventDefault();
                   settings.nextQuestion();
               });

            $form.find(settings.skipButtonSelector)
               .off('click.configureSCMForm')
               .on('click.configureSCMForm', function (e) {
                   e.preventDefault();
                   settings.skip();
               });
            $form.find(settings.cancelButtonSelector)
                .off('click.configureSCMForm')
                .on('click.configureSCMForm', function (e) {
                    e.preventDefault();
                    if (!settings.cancel) {
                        $form.hide();
                        SCM.hideModal();
                    } else {
                        settings.cancel();
                    }
                });
        });
    };


    $.fn.viewMore = function (data) {

        var settings = $.extend({
            hiddenSelector: '.read-more',
            readMoreButtonSelector: '#readMore',
            readMoreText: 'Read More',
            readLessText: 'Read Less'
        }, data);

        return this.each(function () {

            var $readMore = $(settings.hiddenSelector);
            $readMore.hide();

            $(settings.readMoreButtonSelector).on('click', function (e) {
                e.preventDefault();

                $readMore.fadeToggle();
            });

        });
    };


    $.fn.scmTinyMCE = function () {
        $('.mceOpen.mce_forecolor').show();
        $('.mce_forecolor .mceLast .mceIconOnly').show();
        $('.mceOpen.mce_backcolor').show();
        $('.mceOpen.mce_backcolor .mceIconOnly').show();
        return this.each(function () {
            $(this).tinymce({
                gecko_spellcheck: true,
                theme: "advanced",
                theme_advanced_buttons1: "bold,italic,underline,|,bullist,numlist,|,sub,sup,|,charmap,|,forecolor,backcolor,|,link", //spellchecker
                theme_advanced_buttons2: "",
                theme_advanced_buttons3: "",
                plugins: "inlinepopups",
                theme_advanced_statusbar_location: null,
                oninit: function (mce) {

                    //ensure configured for radiobutton disable
                    var $inputElement = $('#' + mce.editorId + '[data-rb-enable-name]');
                    var $rb = $('input:radio[name="' + $inputElement.data('rbEnableName') + '"]');
                    if ($rb.length > 0 &&
                        $rb.val().toString().toLowerCase() != $inputElement.data('rbEnableValue').toString().toLowerCase()) {
                        $inputElement.attr('disabled', 'disabled');
                        var tinyEditor = tinymce.editors[$inputElement[0].id];
                        if (tinyEditor) {
                            tinyEditor.getBody().setAttribute('contenteditable', false);
                        }
                    }
                }
            });
        });
    };


    $.fn.scmTimer = function (data) {
        return this.each(function () {
            var $this = $(this);

            var settings = $.extend({
                h: 0,
                m: 0,
                s: 0,
                hs: 0,
                stop: false,
                milliseconds: 150,
                intervalCheck: null,
            }, data);

            if (settings.stop) {
                clearInterval($this.data('scmTimerToken'));
                return;
            }

            var formatTime = function (i) {
                if (i < 10) {
                    i = "0" + i;
                }
                return i;
            };

            var startTime = (new Date()).getTime();

            var showTime = function () {
                $this.text(formatTime(settings.h) + ":" + formatTime(settings.m) + ":" + formatTime(settings.s) + ":" + formatTime(settings.hs));
            };


            showTime();
            $this.data('scmTimerToken', setInterval(function () {

                if (!$this.is(':visible')) {
                    clearInterval($this.data('scmTimerToken'));
                    return;
                }

                var newTime = (new Date()).getTime();
                var ticksSinceLastInterval = newTime - startTime;
                settings.hs += Math.floor(ticksSinceLastInterval / 10);
                startTime = newTime;
                if (settings.hs >= 100) {
                    settings.s += Math.floor(settings.hs / 100);
                    settings.hs = settings.hs % 100;

                    if (settings.s >= 60) {
                        settings.m += Math.floor(settings.s / 60);
                        settings.s = settings.s % 60;
                    }

                    if (settings.m >= 60) {
                        settings.h += Math.floor(settings.m / 60);
                        settings.m = settings.m % 60;
                    }
                }

                showTime();

                if (settings.intervalCheck) {
                    if (!settings.intervalCheck(settings)) {
                        clearInterval($this.data('scmTimerToken'));
                        return;
                    }
                }

            }, settings.milliseconds));

        });
    };


    $.fn.wkTimer = function (data) {
        return this.each(function () {
            var $this = $(this);

            var settings = $.extend({
                h: 0,
                m: 0,
                s: 0,
                hs: 0,
                stop: false,
                milliseconds: 150,
                intervalCheck: null,
            }, data);

            if (settings.stop) {
                clearInterval($this.data('wkTimerToken'));
                return;
            }

            var formatTime = function (i) {
                if (i < 10) {
                    i = "0" + i;
                }
                return i;
            };

            var startTime = (new Date()).getTime();

            var showTime = function () {
                $this.text(formatTime(settings.m) + ":" + formatTime(settings.s));
            };


            showTime();
            $this.data('wkTimerToken', setInterval(function () {

                if (!$this.is(':visible')) {
                    clearInterval($this.data('wkTimerToken'));
                    return;
                }

                var newTime = (new Date()).getTime();
                var ticksSinceLastInterval = newTime - startTime;
                settings.hs += Math.floor(ticksSinceLastInterval / 10);
                startTime = newTime;
                if (settings.hs >= 100) {
                    settings.s += Math.floor(settings.hs / 100);
                    settings.hs = settings.hs % 100;

                    if (settings.s >= 60) {
                        settings.m += Math.floor(settings.s / 60);
                        settings.s = settings.s % 60;
                    }

                    if (settings.m >= 60) {
                        settings.h += Math.floor(settings.m / 60);
                        settings.m = settings.m % 60;
                    }
                }

                showTime();

                if (settings.intervalCheck) {
                    if (!settings.intervalCheck(settings)) {
                        clearInterval($this.data('wkTimerToken'));
                        return;
                    }
                }

            }, settings.milliseconds));

        });
    };
})(jQuery);