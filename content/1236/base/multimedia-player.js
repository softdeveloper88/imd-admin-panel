$(document).ready(function () {

    if ($('.BrightcoveExperience').length != 0) {
        var jsSrc = "http://admin.brightcove.com.ezproxylocal.library.nova.edu/js/BrightcoveExperiences.js";
        if (location.protocol == "https:") {
            jsSrc = "https://sadmin-brightcove-com.ezproxylocal.library.nova.edu/js/BrightcoveExperiences.js";
        }
        $.getScript(jsSrc, function() {
            if (location.protocol != "https:") {
                $(".BrightcoveExperience").find("param[name='secureConnections']").remove();
                $(".BrightcoveExperience").find("param[name='secureHTMLConnections']").remove();
            }
            brightcove.createExperiences();
        });
    }
});

/**** Brightcove Learning Services Module ****/
/* Note:  to add events from the player such as when the play button is pressed on a particular video, look at Bates example */
var BCLS = (function () {
    // variables
    // public functions and data
    return {
        /**** template loaded event handler ****/
        onTemplateLoad: function (experienceId) {
        },
        /**** template ready event handler ****/
        onTemplateReady: function (evt) {
        },
    };
}());


