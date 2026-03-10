// TODO: Deprecate JS logic on the Advanced Search Page
//		 Instead, use standard HTML forms to submit advanced 
//		 search queries. Presentation JS should be moved to 
//		 other global script files and any advancedsearch.js
//		 files should be deleted.


// Advanced Search
// ========================================

var SCM = SCM || {};

SCM.AdvancedSearch = {};

SCM.AdvancedSearch.configSettings = {
    preSelectSingleBookFacet: "true"
};



// ----
// Global Variables
// ----

var textCharectorLimit = $("#hfSolrMaxAllowSearchChar").val(); // hidden field on the master page of the client


// ----
// Add Subscription Parameter to URL
// ----

function AppendSubscriptionParameterToUrl(redirectUrl) {

    var subOnlyParam = "&subonly=true",
        isSubOnly = $("#hfEnableSubscriptionFilter").val().toLowerCase() == "true",
        url = redirectUrl;

    // check for subscription only value
    if (isSubOnly) {
        // add the subscription parameter to the URL
        var url = redirectUrl + subOnlyParam;
    }

    return url;
}


// ----
// Date
// ----

//For todays date;
// Source: http://stackoverflow.com/questions/10211145/getting-current-date-and-time-in-javascript
Date.prototype.today = function () {
    return (((this.getMonth() + 1) < 10) ? "0" : "") + (this.getMonth() + 1) + "/" + ((this.getDate() < 10) ? "0" : "") + this.getDate() + "/" + this.getFullYear();
};

// set the character limit if none is already set
if (textCharectorLimit == null || textCharectorLimit == '') {
    textCharectorLimit = "255";
}

// compose a valid date
function isValidDate(date) {
    var matches = /^(\d{2})[-\/](\d{2})[-\/](\d{4})$/.exec(date);
    if (matches == null) return false;
    var d = matches[2];
    var m = matches[1] - 1;
    var y = matches[3];
    var composedDate = new Date(y, m, d);
    return composedDate.getDate() == d &&
            composedDate.getMonth() == m &&
            composedDate.getFullYear() == y;
}

// check if its only a year
function isYearOnly(date) {
    var matches = /^(\d{4})$/.exec(date);

    return (matches && (matches[1] > -1));
}

// change year only entrees to full formed dates
function updateYearOnlyToFullDate(dateTxtField, isStartDate) {
    var year = dateTxtField.val();
    var month = null;
    var day = null;
    if (isStartDate) {
        month = '01';
        day = '01';
    } else {
        month = '12';
        day = '31';
    }

    dateTxtField.val(month + "/" + day + "/" + year);

    return dateTxtField.val();
}


// ----
// Set Search Scope
// ----

var micrositeJournalDisplayName = "";
var micrositeJournalId = "";
var solrsearchScope = $("#hfSolrJournalID").val();
var solrBookSearchScope = $("#hfSolrBookID").val();

// TODO: Handle undefined scope

if (typeof solrsearchScope === "undefined") {
    solrsearchScope = ""; //default it to empty string
} else {
    if (solrsearchScope != null) {
        solrsearchScope = solrsearchScope.replace("J", "");
    }
}

if (typeof solrBookSearchScope === "undefined") {
    solrBookSearchScope = ""; //default it to empty string
} else {
    if (solrBookSearchScope != null) {
        solrBookSearchScope = solrBookSearchScope.replace("B", "");
    }
}


$(document).ready(function (event) {


    // ----
    // Check Boxes
    // ----

    // if not looking for books
    if (solrBookSearchScope == null || solrBookSearchScope == '') {

        // 1) disable all books check boxes
        $('#advancedSearch input.advancedSearchBook[type=checkbox]').each(function () {
            $(this).removeAttr("checked");
            $(this).attr("disabled", true);
        });

        $('.advancedAuthorSearch input.advancedSearchBook[type=checkbox]').each(function () {
            $(this).removeAttr("checked");
            $(this).attr("disabled", true);
        });


        // 2) uncheck books radio button 
        $('input.rbPublication[type=radio]').each(function () {
            var isAllBooks = $(this).attr('value') == "B*" ? true : false;
            if (isAllBooks) {
                $(this).removeAttr("checked");
            } else {
                $(this).attr('checked', 'checked');
            }
        });

    } else {
        // it is a book search so.. disable journal stuff

        //1) check boxes
        $('#advancedSearch input.advancedSearchJournal[type=checkbox]').each(function () {
            $(this).removeAttr("checked");
            $(this).attr("disabled", true);
        });

        $('.advancedAuthorSearch input.advancedSearchJournal[type=checkbox]').each(function () {
            $(this).removeAttr("checked");
            $(this).attr("disabled", true);
        });


        // 2) uncheck books radio button 
        $('input.rbPublication[type=radio]').each(function () {
            var isAllJournals = $(this).attr('value') == "J*" ? true : false;
            if (isAllJournals) {
                $(this).removeAttr("checked");
            } else {
                $(this).attr('checked', 'checked');
            }
        });
    }


    // preselect the journal for check box and drop down.
    if ((solrsearchScope != null && solrsearchScope != "") || (solrBookSearchScope != null && solrBookSearchScope != "")) {
        $('.advancedAuthorSearch input:checkbox').each(function () {
            var currentDisplayName = $(this).attr("currentjournaldisplayname");
            var currentText = $(this).attr("text");
            var journalId = $(this).attr("jid");
            var bookId = $(this).attr("bid");
            if (currentDisplayName != null & currentText != null && currentDisplayName == currentText) {
                if (journalId == solrsearchScope) {
                    // alert(journalId);
                    (this).checked = true;

                    //get the journal display Name for the microsite journal.
                    micrositeJournalDisplayName = currentText;
                    micrositeJournalId = journalId;

                    //exit loop
                    return false;
                }
            } else if (bookId != null && bookId != '') {
                if (bookId == solrBookSearchScope || solrBookSearchScope === '*') {
                    (this).checked = true;
                }
            }
        });

        $('#advancedSearch input:checkbox').each(function () {
            var currentDisplayName = $(this).attr("currentjournaldisplayname");
            var currentText = $(this).attr("text");
            var journalId = $(this).attr("jid");
            var bookId = $(this).attr("bid");

            if (currentDisplayName != null & currentText != null && currentDisplayName == currentText) {
                if (journalId == solrsearchScope) {
                    // alert(journalId);
                    (this).checked = true;

                    //get the journal display Name for the microsite journal.
                    micrositeJournalDisplayName = currentText;
                    micrositeJournalId = journalId;

                    //exit loop
                    return false;
                }
            } else if (bookId != null && bookId != '') {
                //alert('Book ID in advancedSearch is ::' + bookId);
                if (bookId == solrBookSearchScope || solrBookSearchScope === '*') {
                    (this).checked = true;
                }
            }
        });

        $('.citationJournal').each(function () {
            $('option', this).each(function () {
                var jarrayItemValue = $(this).val().split(',');
                if (jarrayItemValue != null && jarrayItemValue[0] == "C") {
                    var journalId = jarrayItemValue[1];
                    if (journalId == solrsearchScope) {
                        // alert(journalId);
                        $(this).attr('selected', 'selected');
                    }
                }
            });
        });

    }

    // ----
    // Title Search
    // ----

    //Title Search function used for the button click and Default behavior of the Title text field.
    function doTitleSearch(title) {

        if (title == null || title == '') {
            alert('Please enter a term to search');
            return;
        } else if (title.length > parseInt(textCharectorLimit)) {
            alert("Please enter a term between 1 to " + textCharectorLimit + " characters");
            return;
        } else {

            var articleTitle = "\"" + title + "\"";
            var targetUrl = "";
            var journalQuery = "";

            if (solrsearchScope) {
                journalQuery = "&fl_JournalID=" + micrositeJournalId + "&f_JournalDisplayName=" + encodeURIComponent($.trim(micrositeJournalDisplayName));
            }

            targetUrl = "/solr/searchresults.aspx?q=" + encodeURIComponent(articleTitle) + "&fd_ArticleTitle=" + encodeURIComponent(articleTitle);//+ "&exPrm_qqq=" + encodeURIComponent("{!payloadDisMaxQParser pf=Tags qf=Tags^0.0000001 payloadFields=Tags v=$q bf=}" + wildCardCharacter);

            if (journalQuery != "") {
                //append journalID and JournalDisplayName querystrings to the url.
                targetUrl = targetUrl + journalQuery;
            } else {
                //ToDo: Check if this is necessary.
                targetUrl = targetUrl + "&allJournals=1";
            }

            window.location.href = AppendSubscriptionParameterToUrl(targetUrl);
        }
    }

    $('#btnAdvancedTitleSearch').click(function () {
        var searchTerm = $('#articleTitle').val();
        doTitleSearch(searchTerm);
    });

    $('#articleTitle').keydown(function (e) {
        if (e.keyCode == 13) {
            var searchTerm = $('#articleTitle').val();
            //alert(searchTerm);

            doTitleSearch(searchTerm);
        }
    });

    // ----
    // Citation Search
    // ----

    //Citation Search
    function doAdvancedCitationSerach() {

        var ctYearValue = $('#citationYear').val();
        var ctVolumeValue = $('#citationVolume').val();
        var ctStartPageValue = $('#citationPage').val();
        var ctJournalValue = $('.citationJournal').val();
        var journalDisplayName = $(".citationJournal option:selected").text();
        var isCurrentJournal = false;

        var citationData = {};
        var validationMessage = "";

        if ((ctJournalValue == null || ctJournalValue == '' || ctJournalValue == "- Select a Journal")) {
            validationMessage = "Please select a journal." + "\n";
        }

        //YEAR
        if ((ctYearValue != null) && (ctYearValue != '') && (ctYearValue != "Yr")) {
            if (isNaN(ctYearValue)) {
                validationMessage = validationMessage + "Year must be numeric." + "\n";
            } else {
                //var rangequery = ctYearValue + "-01-01T00:00:00.000Z TO " + ctYearValue + "-12-31T23:59:59.000Z";
                //Instead of using the ISO format, just using the MM/DD/YYYY format
                var rangequery = "01/01/" + ctYearValue + " TO " + "12/31/" + ctYearValue;
                citationData.rg_ArticleDate = rangequery;
            }
        }


        //VOLUME
        if ((ctVolumeValue != null) && (ctVolumeValue != '') && (ctVolumeValue != "Vol")) {
            if (isNaN(ctVolumeValue)) {
                validationMessage = validationMessage + "Volume must be numeric.";
            } else {
                citationData.fd_Volume = ctVolumeValue;
            }
        }

        if (ctStartPageValue != '' && ctStartPageValue != "1st Pg") {
            citationData.fd_StartPage = ctStartPageValue;
        }

        if (validationMessage.length > 0) {
            //validation failed!
            alert(validationMessage);
            return false;
        }

        //CSV will contain 3 elements: First element will be either "C" (current journal) or "L" (legacy journal);Second element will be the JournalID;Third element will be JournalHistoricalAttributesID
        var jarray = ctJournalValue.split(',');
        if (jarray[0] == "C") {
            //Current Journal: Results should include all articles from current journal and all the legacy journals associated with it.
            //Pass just the JournalID
            citationData.fl_JournalID = jarray[1];
            isCurrentJournal = true;

        } else {
            //Legacy: Results should include only articles published under this legacy journal name.
            //Pass the LegacyHistID to get accurate results.
            citationData.fl_JournalHistID = jarray[2];
        }

        //Pass Journal Display Name so Journal is preselected on the results page and ArticleClientType facet (dependent on JournalDisplayName) is displayed!
        //Encode the JournalDisplayName to make sure DisplayNames which have "&" or "-" or other characters are intrepreted correctly.

        //Add Relevancy Parameter
        //var wildCardCharacter = "\"" + "*:*" + "\"";
        //citationData.exPrm_qqq = "{!payloadDisMaxQParser pf=Tags qf=Tags^0.0000001 payloadFields=Tags v=$q bf=}" + wildCardCharacter;

        var redirectUrl = $.param.querystring('/solr/searchresults.aspx', citationData);

        //NOTE:
        //It appears (http://api.jquery.com/jQuery.param/) it is not possible to encode using jQuery.param( obj )
        //As a result, journalFacetName is appended to the redirectUrl variable below (after it is encoded using encodeURIComponent)
        //Journal Display Name needs to be URL encoded
        //ToDo:Because the Journal list includes legacy journals, when a legacy journal is selected, ArticleClientType facet will not be displayed because the ArticleClientType facet depends on JournalDisplayName and not LegacyJournalDisplayName.
        var journalFacetName = "";  //encodeURIComponent($.trim(journalDisplayName));
        if (isCurrentJournal) {
            journalFacetName = '&f_JournalDisplayName=' + encodeURIComponent($.trim(journalDisplayName));
        } else {
            //ToDo:Revisit this!
            //We can certainly make "LegacyJournalDisplayName" a facet and then create a dependency between LegacyJournalDisplayName & ArticleClientType but
            journalFacetName = '&fd_LegacyJournalDisplayName=' + encodeURIComponent($.trim(journalDisplayName));
        }

        redirectUrl = redirectUrl + journalFacetName;

        //window.location.href = redirectUrl;
        window.location.href = AppendSubscriptionParameterToUrl(redirectUrl);
    }

    //Citation Search Click
    $('#btnAdvancedCitationSearch').click(function () {
        doAdvancedCitationSerach();
    });

    //Enter key -- Advanced Citation Search
    $('#btnAdvancedCitationSearch').keydown(function (e) {
        if (e.keyCode == 13) {
            doAdvancedCitationSerach();
        }
    });

    // ----
    // Keyword Search
    // ----

    //KeyWord Search
    function doAdvancedKeyWordSearch() {
        // alert("hello");
        var radioCheck = '1';
        var startDate = null;
        var endDate = null;
        var searchTerm = null;
        var journalIds = [];
        var bookIds = [];
        var journalHistIds = [];
        var data = {};
        var queryTerm = null;
        var queryTermWithQuotes = null;
        var journalDisplayName = null;
        var currentJournalDisplayName = null;
        var bookDisplayName = null;
        var isBookSearch = false;
        var isJournalSearch = false;

        searchTerm = $('#advancedSearch .search-field').val();

        if (searchTerm == null || searchTerm == '') {
            alert('Please enter a term to search');
            return;
        } else if (searchTerm.length > parseInt(textCharectorLimit)) {
            alert("Please enter a term between 1 to " + textCharectorLimit + " characters.");
            return;
        } else {
            data.q = searchTerm;
        }
        $('#advancedSearch input.anyAllExact[type=radio]').each(function () {
            //if ($(this).is(':checked')) {
            if ((this).checked) {
                radioCheck = $(this).attr('id');
                // alert(radioCheck);
            }
        });

        queryTermWithQuotes = '"' + searchTerm + '"';

        switch (radioCheck) {
            case "1":
                data.hd = "advancedAny";
                queryTerm = searchTerm;                 //Any does NOT need quotes around the term ("q").
                break;
            case "2":
                data.hd = "advancedAll";
                queryTerm = searchTerm;                 //All does NOT need quotes around the term ("q")
                break;
            case "3":
                queryTerm = queryTermWithQuotes;        //exact phrase need quotes around the term ("q")
                break;
            default:
        }

        //Apply relevancy parameter to all the options:
        data.q = encodeURIComponent($.trim(queryTerm));
        //data.exPrm_qqq = "{!payloadDisMaxQParser pf=Tags qf=Tags^0.0000001 payloadFields=Tags v=$q bf=}" + queryTermWithQuotes;

        var authorTextValue = $('#advancedSearch .authorSearch').val();
        if (authorTextValue != null && authorTextValue != '') {
            //data.fd_Authors = authorTextValue;

            //In view of the Author boosting changes, passing author in the url as a querystring
            data.author = authorTextValue;
        }

        //Start and End Dates
        startDate = $('#startDateSemanticSearch').val();
        //endDate = $('#endDateSemanticSearch').val() == '' ? Date.now().toString : $('#endDateSemanticSearch').val();
        if (startDate != null && startDate != '' && startDate != 'mm/dd/yyyy') {
            // check if it is a valid date
            if (isYearOnly(startDate)) {
                startDate = updateYearOnlyToFullDate($('#startDateSemanticSearch'), true);
            } else if (!isValidDate(startDate)) {
                alert("please enter valid start date");
                return;
            }// if start date is specified and enddate is not specified, default the end date to current date
            if ($('#endDateSemanticSearch').val() === '') {
                $('#endDateSemanticSearch').val((new Date()).today());
                endDate = $('#endDateSemanticSearch').val();
            } else {
                endDate = $('#endDateSemanticSearch').val();
                if (isYearOnly(endDate)) {
                    endDate = updateYearOnlyToFullDate($('#endDateSemanticSearch'), false);
                } else if (!isValidDate(endDate) || new Date(endDate) < new Date(startDate)) {
                    alert("please enter valid end date");
                    return;
                }
            }
            data.rg_ArticleDate = startDate + ' TO ' + endDate;
        }


        //''chkAdvancedSearchJournal
        $("#advancedSearch input.rbPublication[type=radio]").each(function () {
            if ((this).checked) {
                isJournalSearch = $(this).attr('value') == "J*" ? true : false;
                isBookSearch = $(this).attr('value') == "B*" ? true : false;
            }
        });

        $('#advancedSearch #chkAdvancedSearchJournal:checked').each(function () {
            isJournalSearch = true;
            currentJournalDisplayName = $(this).attr("currentjournaldisplayname");
            journalDisplayName = $(this).attr("text");
            journalHistIds.push($(this).attr("value"));
            journalIds.push($(this).attr("jid"));
        });

        $('#advancedSearch #chkAdvancedSearchBook:checked').each(function () {
            isBookSearch = true;
            bookDisplayName = $(this).attr("text");
            bookIds.push($(this).attr("bid"));
        });

        //chkAdvancedSearchBook
        var redirectUrl = $.param.querystring('/solr/searchresults.aspx', data);
        if (isJournalSearch) {
            var journalHistIdquery = journalHistIds.join(' OR ');
            var journalIdquery = journalIds.join(' OR ');
            redirectUrl = redirectUrl + "&restypeid=3";
            if (journalHistIds.length == 1) {
                var journalFacetName = encodeURIComponent($.trim(journalDisplayName));
                if (journalDisplayName == currentJournalDisplayName) {
                    journalQuery = "&fl_JournalID=" + journalIdquery + "&f_JournalDisplayName=" + journalFacetName;
                } else {
                    journalQuery = "&fl_JournalID=" + journalIdquery + "&f_JournalDisplayName=" + encodeURIComponent($.trim(currentJournalDisplayName)) + "&fd_LegacyJournalDisplayName=" + journalFacetName;
                }
                redirectUrl = redirectUrl + journalQuery;
            } else if (journalHistIds.length > 1) {
                //multiple journals selected; some could be Legacy and some could be Current
                //Pass JournalHistID because the list could contain some legacy journals.
                var journalHistIdQueryString = "&fl_JournalHistID=" + journalHistIdquery;

                redirectUrl = redirectUrl + journalHistIdQueryString;
            } else if (journalHistIds.length == 0) {
                //If all journals, tag this to querystring
                redirectUrl = redirectUrl + "&allJournals=1";
            }

            // alert(redirectUrl);
        }

        //TI-16370 - WKHL has Book Content only and the publicationType option (Journals/Books) section is hidden. So isBookSearch is not set at this point.
        //This version is currently used by ASHA, AJOT, and WKHL. ASHA and AJOT have journal only content. This should be okay for now!
        isBookSearch = (solrBookSearchScope != null && solrBookSearchScope != "" && !isJournalSearch);

        if (isBookSearch) {
            redirectUrl = redirectUrl + getBookQueryParams(bookIds, bookDisplayName);
        }
        //window.location.href = redirectUrl;
        window.location.href = AppendSubscriptionParameterToUrl(redirectUrl);
    }

    //Enter key -- Advanced Semantic Search
    $('#advancedSearchQueryTerm').keydown(function (e) {
        if (e.keyCode == 13) {
            doAdvancedKeyWordSearch();
        }
    });

    //Semantic Search Click
    $('#btnAdvancedSearch, #btnAdvancedSearchTop').on('click', function () {
        doAdvancedKeyWordSearch(); //advancedKeyWordSearch
    });

    // ----
    // Author Search
    // ----

    //Author Search
    function doAdvancedAuthorSearch() {

        var startDate = null;
        var endDate = null;
        var searchTerm = null;
        var journalIds = [];
        var bookIds = [];
        var journalHistIds = [];
        var journalItems = [];
        var data = {};
        var journalDisplayName = null;
        var currentJournalDisplayName = null;
        var bookDisplayName = null;
        var isBookSearch = false;
        var isJournalSearch = false;


        searchTerm = $('.advancedAuthorSearch .search-field').val();
        if (searchTerm == null || searchTerm == '') {
            alert('Please enter a term to search');
            return;
        } else if (searchTerm.length > parseInt(textCharectorLimit)) {
            alert("Please enter a term between 1 to " + textCharectorLimit + " characters.");
            return;
        } else {
            //Author relevancy/boosting changes
            data.author = encodeURIComponent($.trim(searchTerm));
            data.q = encodeURIComponent($.trim(searchTerm));
            //data.fd_Authors = searchTerm;
        }

        //Start and End Dates

        startDate = $('#startDateAuthor').val();
        //endDate = $('#endDateAuthor').val() == '' ? Date.now().toString : $('#endDateAuthor').val();
        if (startDate != null && startDate != '' && startDate != 'mm/dd/yyyy') {
            if (isYearOnly(startDate)) {
                startDate = updateYearOnlyToFullDate($('#startDateAuthor'), true);
            }

            if (!isValidDate(startDate)) {
                alert("please enter valid start date");
                return;
            }

            if ($('#endDateAuthor').val() === '') {
                $('#endDateAuthor').val((new Date()).today());
                endDate = $('#endDateAuthor').val();
            } else {
                endDate = $('#endDateAuthor').val();
                if (isYearOnly(endDate)) {
                    endDate = updateYearOnlyToFullDate($('#endDateAuthor'), false);
                }
            }

            if (!isValidDate(endDate) || new Date(endDate) < new Date(startDate)) {
                alert("please enter valid end date");
                return;
            }

            data.rg_ArticleDate = startDate + ' TO ' + endDate;
        }

        $(".advancedAuthorSearch input.rbPublication[type=radio]").each(function () {
            if ((this).checked) {
                isJournalSearch = $(this).attr('value') == "J*" ? true : false;
                isBookSearch = $(this).attr('value') == "B*" ? true : false;
            }
        });

        $('.advancedAuthorSearch #chkAuthorJournal:checked').each(function () {
            isJournalSearch = true;
            currentJournalDisplayName = $(this).attr("currentjournaldisplayname");
            journalDisplayName = $(this).attr("text");
            journalHistIds.push($(this).attr("value"));
            journalIds.push($(this).attr("jid"));
        });
        $('#advancedSearch #chkAdvancedSearchBook:checked').each(function () {
            isBookSearch = true;
            bookDisplayName = $(this).attr("text");
            bookIds.push($(this).attr("bid"));
        });

        var redirectUrl = $.param.querystring('/solr/searchresults.aspx', data);
        if (isJournalSearch) {
            var journalHistIdquery = journalHistIds.join(' OR ');
            var journalIdquery = journalIds.join(' OR ');
            redirectUrl = redirectUrl + "&restypeid=3";
            if (journalHistIds.length == 1) {
                var journalFacetName = encodeURIComponent($.trim(journalDisplayName));
                if (journalDisplayName == currentJournalDisplayName) {
                    journalQuery = "&fl_JournalID=" + journalIdquery + "&f_JournalDisplayName=" + journalFacetName;
                } else {
                    journalQuery = "&fl_JournalID=" + journalIdquery + "&f_JournalDisplayName=" + encodeURIComponent($.trim(currentJournalDisplayName)) + "&fd_LegacyJournalDisplayName=" + journalFacetName;
                }
                redirectUrl = redirectUrl + journalQuery;
            } else if (journalHistIds.length > 1) {
                //multiple journals selected; some could be Legacy and some could be Current
                //Pass JournalHistID because the list could contain some legacy journals.
                var journalHistIdQueryString = "&fl_JournalHistID=" + journalHistIdquery;

                redirectUrl = redirectUrl + journalHistIdQueryString;
            } else if (journalHistIds.length == 0) {
                //If all journals, tag this to querystring
                redirectUrl = redirectUrl + "&allJournals=1";
            }

            // alert(redirectUrl);

        }
        if (isBookSearch) {
            redirectUrl = redirectUrl + getBookQueryParams(bookIds, bookDisplayName);
        }

        //window.location.href = redirectUrl;
        window.location.href = AppendSubscriptionParameterToUrl(redirectUrl);
    }

    //Author Search Click
    $('#btnAdvancedAuthorSearch, #btnAdvancedAuthorSearchTop').on('click', function () {
        //alert('Author Search');
        doAdvancedAuthorSearch();
    });


    //Enter key -- Advanced Author Search
    $('#advancedAuthorSearchQueryTerm').keydown(function (e) {
        if (e.keyCode == 13) {
            doAdvancedAuthorSearch();
        }
    });

    // ----
    // DOI Search
    // ----

    //DOI Keypress
    $('#Doi').keydown(function (e) {
        if (e.keyCode == 13) {
            GetDoiUrl();
            $('#aDoiSearch').click();
        }
    });

    // ----
    // Book Query
    // ----
    function getBookQueryParams(bookIds, bookDisplayName) {
        var bookQueryString = "&restypeid=1";
        var bookIdQuery = bookIds.join(' OR ');

        if (SCM.AdvancedSearch.configSettings.preSelectSingleBookFacet == "true" && bookIds.length === 1) {
            bookQueryString = bookQueryString + "&f_BookDisplayName=" + encodeURIComponent($.trim(bookDisplayName)) + "&fl_BookID=" + bookIdQuery;
        } else if (bookIds.length > 0) {
            bookQueryString = bookQueryString + "&fl_BookID=" + bookIdQuery;
        } else if (bookIds.length === 0) {
            bookQueryString = bookQueryString + "&allBooks=1";
        }

        return bookQueryString;
    }

    // ----
    // Expand and Collapse Sections
    // ----
    // Expand and collapse sections
    $('.toggle-expanded').on('click', function () {
        $(this).parents('.search-module').toggleClass('collapsed').toggleClass('expanded');
    });


}); // END $(document).ready()





// ----
// Datepicker Keyboard Adjustments
// ----
// This prevents the form submitting when pressing enter while on the datepicker. 
// It is waaaaaaayy too long. 
$(function () {
    try {


        $("#startDateSemanticSearch").bind("keydown", function (e) {
            // http://stackoverflow.com/questions/15235499/jquery-ui-datepicker-prevent-enter-selecting-when-readonly
            if (e.which == 13) {
                var startDateSemanticSearch = $('#startDateSemanticSearch').val();
                if (isYearOnly(startDateSemanticSearch)) {
                    updateYearOnlyToFullDate($('#startDateSemanticSearch'), true);
                    e.preventDefault();
                    e.stopImmediatePropagation();
                    return false;
                }
            }
        });

        $("#endDateSemanticSearch").bind("keydown", function (e) {
            // http://stackoverflow.com/questions/15235499/jquery-ui-datepicker-prevent-enter-selecting-when-readonly
            if (e.which == 13) {
                var endDateSemanticSearch = $('#endDateSemanticSearch').val();
                if (isYearOnly(endDateSemanticSearch)) {
                    updateYearOnlyToFullDate($('#endDateSemanticSearch'), true);
                    e.preventDefault();
                    e.stopImmediatePropagation();
                    return false;
                }
            }
        });

        $("#startDateAuthor").bind("keydown", function (e) {
            // http://stackoverflow.com/questions/15235499/jquery-ui-datepicker-prevent-enter-selecting-when-readonly
            if (e.which == 13) {
                var startDateAuthor = $('#startDateAuthor').val();
                if (isYearOnly(startDateAuthor)) {
                    updateYearOnlyToFullDate($('#startDateAuthor'), true);
                    e.preventDefault();
                    e.stopImmediatePropagation();
                    return false;
                }
            }
        });

        $("#endDateAuthor").bind("keydown", function (e) {
            // http://stackoverflow.com/questions/15235499/jquery-ui-datepicker-prevent-enter-selecting-when-readonly
            if (e.which == 13) {
                var endDateAuthor = $('#endDateAuthor').val();
                if (isYearOnly(endDateAuthor)) {
                    updateYearOnlyToFullDate($('#endDateAuthor'), true);
                    e.preventDefault();
                    e.stopImmediatePropagation();
                    return false;
                }
            }
        });


    } catch (e) { }
});










