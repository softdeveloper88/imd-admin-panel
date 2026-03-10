// ----
// SCM.SharedControls.PDFAccess.js
// checks a user's access to a PDF and launches the PDF or a no-access modal
//
// The PDF links, located in multiple widgets, contain HTML 5 attributes like data-article-id, data-article-url, data-ajax-url, data-issue-id ...
// In ToolboxPdf.cshtml, the article PDF link is identified by classes al-link and pdfaccess; the issue PDF link is identified by classes al-link and issue-pdfLink
//
// The noAccessReveal modal is in Site.Master in the client project; it is used for both the article and issue PDF "no access" modals
// In the noAccessReveal modal, the article purchase link has id=articleLinkToPurchase, the issue purchase modal has class=issue-purchase-modal
//
// There are 2 kinds of Issue PDFs: TOC.pdf (available to anyone) and fullissue.pdf (only authenticated users may access)
// ----

var SCM = SCM || {};

(function(pdf, $) {
    // ----
    // Private variables and functions
    // ----
    function formatIssuePurchaseLink(issuePurchaseUrl, id) {
        // If the purchase URL contains "resourceid=", format the "resourceid=" portion of the querystring with the current issue id
        var revisedIssuePurchaseUrl = issuePurchaseUrl;

        if (issuePurchaseUrl.toLowerCase().indexOf("resourceid=") >= 0) {
            var pattern = /resourceID=\{0\}|resourceID=\d+/i;
            revisedIssuePurchaseUrl = issuePurchaseUrl.replace(pattern, "resourceid=" + id);
        }

        return revisedIssuePurchaseUrl;
    }

    function logErrors(jqXHR, textStatus, errorThrown) {
        if (window.console) {
            var err = eval("(" + jqXHR.responseText + ")");
            console.log('error: ' + err);
            console.log('status: ' + textStatus);
        }
    }

    function openPDF(PDFUrl) {
        window.location.href = PDFUrl;
    }

    function openNoAccessModalArticle(articlePdfAnchor, articldeID) {
        // remove data attributes so ajax call doesn't happen if PDF link is clicked a 2nd time.
        // instead, link the PDF link directly with the No-Access modal
        articlePdfAnchor.attr({ 'data-reveal-id': 'noAccessReveal', 'data-reveal': '' }).removeAttr('data-ajax-url');
        var articleUrl = '/article.aspx?articleid=' + articldeID + '#purchaseSubscriptionBox';
        pdf.$noAccessModal.find('#articleLinkToPurchase').attr('href', articleUrl);
        pdf.$noAccessModal.foundation('reveal', 'open');
    }

    function openNoAccessModalArticleSeo(articlePdfAnchor, articldeID, seoUrl) {
        // remove data attributes so ajax call doesn't happen if PDF link is clicked a 2nd time.
        // instead, link the PDF link directly with the No-Access modal
        articlePdfAnchor.attr({ 'data-reveal-id': 'noAccessReveal', 'data-reveal': '' }).removeAttr('data-ajax-url');
        if (seoUrl == "DO_NOT_USE") {
            pdf.$noAccessModal.find('#articleLinkToPurchase').remove();
        } else {
            var articleUrl = seoUrl;
            pdf.$noAccessModal.find('#articleLinkToPurchase').attr('href', articleUrl);
        }
        pdf.$noAccessModal.foundation('reveal', 'open');
    }

    function openNoAccessModalIssue(issuePurchaseUrl, id) {
        var issueUrl = formatIssuePurchaseLink(issuePurchaseUrl, id);
        pdf.$noAccessModal.find('.aIssuePurchaseLink').attr('href', issueUrl);
        pdf.$noAccessModal.foundation('reveal', 'open');
    }


    // ----
    // Public variables and methods
    // ----

    // making modal selector public so it can be overriden in the client implementation
    pdf.$noAccessModal = $('#noAccessReveal');

    pdf.checkArticlePDFAccess = function (articlePdfAnchor) {
        var id = articlePdfAnchor.attr('data-article-id'),
            url = articlePdfAnchor.attr('data-article-url'),
            ajaxUrl = articlePdfAnchor.attr('data-ajax-url'),
            baseSiteUrl = $("#hfSiteURL");
        var seoUrl = "";
        if (articlePdfAnchor.attr('data-article-seo-url') != null) {
            seoUrl = articlePdfAnchor.attr('data-article-seo-url');
        }
        if (typeof baseSiteUrl != "undefined" && typeof baseSiteUrl.val() != "undefined" && baseSiteUrl != '') {
            ajaxUrl = "//" + baseSiteUrl.val() + ajaxUrl;
        }
        $.ajax({
            type: "POST",
            url: ajaxUrl,
            data: { aId: id },
            traditional: true,
            success: function (access) {
                if (access.Success) {
                    openPDF(url);
                } else {
                    if (seoUrl.length > 0) {
                        openNoAccessModalArticleSeo(articlePdfAnchor, id, seoUrl);
                    } else {
                        openNoAccessModalArticle(articlePdfAnchor, id);
                    }
                }
            },
            error: function (jqXHR, textStatus, errorThrown) {
                logErrors(jqXHR, textStatus, errorThrown);
            }
        });
    };


    pdf.checkIssuePDFAccess = function (issuePdfAnchor) {
        var id = issuePdfAnchor.attr('data-issue-id'),
            url = issuePdfAnchor.attr('data-issue-url'),
            ajaxUrl = issuePdfAnchor.attr('data-ajax-issue-url'),
            issuePurchaseUrl = pdf.$noAccessModal.find('.aIssuePurchaseLink').attr('href');

        if (url.toLowerCase().indexOf('/toc.pdf') > -1) {
            window.location.href = url;
            return;
        }

        $.ajax({
            type: "POST",
            url: ajaxUrl,
            data: { issueId: id },
            traditional: true,
            success: function (access) {
                if (access.Success) {
                    openPDF(url);
                } else {
                    openNoAccessModalIssue(issuePurchaseUrl, id);
                }
            },
            error: function (jqXHR, textStatus, errorThrown) {
                logErrors(jqXHR, textStatus, errorThrown);
            }
        });
    };

    pdf.bindUiEvents = function() {
        // Article PDFs
        $(document).on('click', '.al-link.pdfaccess', function () {
            $(document).foundation();
            pdf.$noAccessModal.foundation('reveal', 'close');
            pdf.$noAccessModal.find('#articleLinkToPurchase').show();
            pdf.$noAccessModal.find('.issue-purchase-modal').hide();

            if (!$(this).attr('data-reveal-id')) {
                pdf.checkArticlePDFAccess($(this));
            }
        });

        // Make sure modal closes when the "x" is clicked
        $(document).on('click', '.close-reveal-modal', function () {
            $(this).parents('.reveal-modal').foundation('reveal', 'close');
        });

        // Issue PDFs
        $(document).on('click', '.al-link.issue-pdfLink', function () {
            pdf.$noAccessModal.foundation('reveal', 'close');
            pdf.$noAccessModal.find('#articleLinkToPurchase').hide();
            pdf.$noAccessModal.find('.issue-purchase-modal').show();

            pdf.checkIssuePDFAccess($(this));
        });
    };

    pdf.init = function() {
        pdf.bindUiEvents();
    };

})(SCM.PDFAccess = SCM.PDFAccess || {}, jQuery);