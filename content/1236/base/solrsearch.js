//TODO: ADD "fd_SiteId" param with current siteID to limit search to items related to that site... This will remove Bates multimedia and other future WK_Books from results.
var solrSuppressFormSubmit = true;

$(document).ready(function () {
    var searchMaxAllowChars = $("#hfSolrMaxAllowSearchChar").val();
    var autoSuggestRunning = false;
    ////Adding the click event handler to the search button.
    //GlobalSearch Icon Click

    $('#aspnetForm').bind("keyup keypress", function (e) {
        var code = e.keyCode || e.which;
        if (code == 13 && solrSuppressFormSubmit) {
            e.preventDefault();
            return false;
        }
    });

    $('#UmbrellaSearchIcon').click(
        function () {
            var queryText = "";

            queryText = $("#UmbrellaSearchTerm").val();

            //search term should not be blank as well
            if (($.trim(queryText) == "") || (queryText == null) || (queryText == "Search healthlibrary")) {
                alert('Please enter a term to search');
                return false;
            }

            if (!autoSuggestRunning) {
                doSolrSearch(queryText);
            }

            return true;
        });

    $('#UmbrellaHomeSearchIcon').click(
    function () {
        var queryText = "";

        queryText = $("#UmbrellaHomeSearchTerm").val();

        //search term should not be blank as well
        if (($.trim(queryText) == "") || (queryText == null) || (queryText == "Search healthlibrary")) {
            alert('Please enter a term to search');
            return false;
        }

        if (!autoSuggestRunning) {
            doSolrSearch(queryText);
        }

        return true;
    });
    //GlobalSearch Text Enter Keydown
    $("#UmbrellaSearchTerm").keydown(function (e) {
        if (e.keyCode == 13) {
            var queryText = "";
            if ($("#UmbrellaSearchTerm").val()) {
                queryText = $("#UmbrellaSearchTerm").val();
            }

            if (!autoSuggestRunning) {
                doSolrSearch(queryText, searchScope);
            }
        }
    });

    //Index Search Text Enter Keydown
    $("#UmbrellaHomeSearchTerm").keydown(function (e) {
        if (e.keyCode == 13) {
            var queryText = "";
            if ($("#UmbrellaHomeSearchTerm").val()) {
                queryText = $("#UmbrellaHomeSearchTerm").val();
            }

            if (!autoSuggestRunning) {
                doSolrSearch(queryText);
            }
        }
    });


    //MicrositeSearch Icon Click
    $('#MicrositeSearchIcon').click(
        function () {
            var queryText = "";
            var searchScope = "";

            queryText = $("#MicrositeSearchTerm").val();
            //MicrositeSearch Scope
            searchScope = $("#hfSolrJournalID").val();

            //search term should not be blank as well
            if (($.trim(queryText) == "") || (queryText == null) || (queryText == "Search healthlibrary")) {
                alert('Please enter a term to search');
                return false;
            }

            if (!autoSuggestRunning) {
                doSolrSearch(queryText);
            }

            return true;
        });

    //MicrositeSearch Text Enter Keydown
    $("#MicrositeSearchTerm").keydown(function (e) {
        if (e.keyCode == 13) {
            var queryText = "";
            if ($("#MicrositeSearchTerm").val()) {
                queryText = $("#MicrositeSearchTerm").val();
                //alert(queryText);
            }
            if (!autoSuggestRunning) {
                doSolrSearch(queryText);
            }

        }
    });


    $('body').on('click', '.sriTopiclink', function (e) {
        var queryText = $(this).text();
        var searchTerm = queryText.replace(",", ""); //

        doSolrSearch(searchTerm, null);


    });

    //CollectionLink Click (collections.aspx)
    $("a.categoryLink").each(function () {
        var _href = $(this).attr("href");
        var journalId = $("#hfSolrJournalID").val();

        if (journalId == '' || journalId == null) {
            $(this).attr("href", $("#hfGlobalSearchSiteURL").val() + _href);
        } else {
            //microsite
            var journalIdParm = journalId.substr(1, journalId.length);
            $(this).attr("href", "/" + _href + '&fd_JournalID=' + journalIdParm);
        }

    });

    $('body').on('click', '#topicResultshealthlibrary', function (e) {
        var query = location.search;
        //journalId needs to be removed from query -- it's the last param
        query = query.substring(0, query.indexOf("&fd_JournalID"));
        window.location.href = $("#hfGlobalSearchSiteURL").val() + "solr/topicresults.aspx" + query;
    });

    var searchScope = $("#hfSolrJournalID").val();
    function doSolrSearch(queryText) {
        queryText = encodeURIComponent(queryText);

        //Only what they subscribe to for HealthLibrary
        queryText = queryText + "&subonly=true";

        //Add &restypeid=1 for BookResults (No snippets without this)
        queryText = queryText + "&restypeid=1";

        if ($("#hfGlobalSearchSiteURL").val() == undefined) {
            if ($("#currentRotationName").val() == "" && $("#currentSiteId").val() == "" && $("#currentRotationId").val() == "") {
                window.location.href = "/solr/searchresults.aspx?q=" + queryText; 
            }
            else {
                if ($("#currentRotationName").val() == ""){
                    window.location.href = "/solr/searchresults.aspx?q=" + queryText 
                                           + $("#currentSiteId").val() + "&rotationId="
                                           + $("#currentRotationId").val(); //new
                }
                else{
                    window.location.href = "/solr/searchresults.aspx?q=" + queryText + "&f_SubSites=" +
                                           $("#currentRotationName").val() + "&fl_SiteID="
                                           + $("#currentSiteId").val() + "&rotationId="
                                           + $("#currentRotationId").val(); //new
                }
            }
        } else {
            window.location.href = $("#hfGlobalSearchSiteURL").val() + "solr/searchresults.aspx?q=" + queryText;   //new  
        }

    }

});