var SCM = SCM || {};
SCM.__namespace = true;

SCM.eventManager = function($, undefined) {

    var subscribeWidgetRefresh = function(scmActionEnum, refreshData) {

        var settings = $.extend({
            refreshWhenInvisible: false,
            messageContainerSelector: '#divMessage'
        }, refreshData);

        var token = "";
        var refreshFunction = function (data) {
            if (!settings.refreshIf ||
                settings.refreshIf(data)) {
                var $container = $(settings.containerSelector);
                if (settings.refreshWhenInvisible || $container.is(':visible')) {
                    $.ajax({
                        type: "POST",
                        url: settings.url,
                        data: settings.data,
                        dataType: "html",
                        success: function(evt) {
                            $.pubsub('unsubscribe', token);
                            $container.replaceWith(evt).show();
                            if (settings.refreshSuccess) {
                                settings.refreshSuccess(data);
                            }
                        }
                    });
                }
            }
        };
        token = subscribeActionCompleted(scmActionEnum, refreshFunction);
    };

    var subscribe = function(subscriptionMessage, refreshFunction) {
        return $.pubsub('subscribe', subscriptionMessage, refreshFunction);
    };

    var publish = function(subscriptionMessage, data) {
        $.pubsub('publish', subscriptionMessage, data);
    };

    var actionCompletedMsg = "actionCompleted";
    var publishActionCompleted = function (scmActionEnum, data) {
        var settings = $.extend({
            actionEnum: scmActionEnum
        }, data);
        publish(actionCompletedMsg, settings);
    };

    var subscribeActionCompleted = function(scmActionEnum, method) {
        return subscribe(actionCompletedMsg, function(msg, data) {
            if (scmActionEnum === data.actionEnum) {
                method(data);
            }
        });
    };

    var actionRequestMsg = "actionCompleteactionRequest";
    var publishActionRequest = function (scmActionEnum, data) {
        return publish(actionRequestMsg, { actionEnum: scmActionEnum, data: data });
    };

    var subscribeActionRequest = function (scmActionEnum, method) {
        return subscribe(actionRequestMsg, function (msg, data) {
            if (scmActionEnum === data.actionEnum) {
                method(data.data);
            }
        });
    };

    var subscribeActionRequestDisplayResult = function (scmActionEnum, displayContainerSelector) {
        return subscribeActionRequest(scmActionEnum, function (data) {
            var settings = $.extend({
                type: "POST"
            }, data);

            $.ajax({
                type: settings.type,
                url: settings.url,
                data: settings.data,
                dataType: "html",
                success: function (evt) {
                    $(displayContainerSelector).html(evt).show();
                },
                error: function (evt) {
                    alert(evt);
                }
            });

            SCM.hideModal();
        });
    };
    
    return {
        subscribeWidgetRefresh: subscribeWidgetRefresh,
        subscribe: subscribe,
        publish: publish,
        publishActionCompleted: publishActionCompleted,
        subscribeActionCompleted: subscribeActionCompleted,
        publishActionRequest: publishActionRequest,
        subscribeActionRequest: subscribeActionRequest,
        subscribeActionRequestDisplayResult: subscribeActionRequestDisplayResult
    };
}(jQuery);

SCM.eventManager.subscriptionMessages = {
    playVideo: "SCM.PlayVideo"
};