var sgOneThemeModule;

(function($) {
    $(document).ready(function() {
          /**
           * BACK TO TOP MODULE
           **/
          window.sgOneBackToTopModule = function(){
            return {
                  /***
                   * registerBackToTop() - Registers components.
                   **/
                  registerBackToTop: function() {
                  var backToTop = $('#back-to-top');

                  if (backToTop) {
                    backToTop.remove();
                  }

                  console.log("sgOneBackToTopModule:registerBackToTop()");

                  // create it and append it to body
                  backToTop = document.createElement("a");
                  backToTop.id = "back-to-top";
                  backToTop.href = "javascript:window.scrollTo(0,0);";

                  document.body.appendChild(backToTop);


                  //Start listening for scroll events: this is necessary to pick up on minute scroll events on mobile devices (onScroll is not sensitive enough)
                  setInterval("sgOneBackToTopModule.backToTop_onScroll()", 100);
                },

                /***
                 * backToTop_onScroll() - handles minute scroll events
                 **/
                backToTop_onScroll: function () {
                  // if the scroll top is more than the height of the viewport, then show back to top
                  var scrollTop = $(document).scrollTop();
                  var viewportHeight = $(window).height();
                  var backToTop = $('#back-to-top');
                  atTop = scrollTop <= viewportHeight;

                  //console.log("scrollTop=" + scrollTop + "; viewportHeight=" + viewportHeight + "; atTop=" + atTop);

                  if (!atTop) {
                      backToTop.show();
                  } else {
                      backToTop.hide();
                  }
                }
            };
          }();

          /**
           * BOOKMARK MODULE
           **/
          window.sgOneBookmarksModule = function(){
            return {
                  isInitialized: false,

                  /***
                   * init - Initializes the module.
                   **/
                  init: function() {
                    console.log("sgOneBookmarksModule:init()");

                    if (!this.isInitialized) {
                      console.log("sgOneBookmarksModule:initializing...")
                      sgOneBookmarksModule.mount();
                      this.isInitialized = true;
                      console.log("sgOneBookmarksModule:initialized!")
                    }
                  },

                /***
                 * mount() - Attaches components if they were not previously attached.
                 **/
                mount: function() {
                  var bookmarkControls = $('BookmarkControls');

                  // attach the notes badge
                  var notesBadge = $("<a></a>");
                  notesBadge.attr("id", "notes-badge");
                  notesBadge.attr("href", "sanfordapp://add-notes");

                  var notesImage = $("<img src='icon_add_notes.png' alt='notes' />");

                  bookmarkControls.append(notesBadge);
                  notesBadge.append(notesImage);

                  // attach the bookmark badge
                  var bookmarkBadge = $("<a></a>");
                  bookmarkBadge.attr("id", "bookmark-badge");
                  bookmarkBadge.attr("href", "sanfordapp://add-bookmark");

                  var bookmarkImage = $("<img src='icon_add_bookmark.png' alt='bookmark' />");

                  bookmarkControls.append(bookmarkBadge);
                  bookmarkBadge.append(bookmarkImage);

                  sgOneBookmarksModule.setNotes("");
                },

                /***
                 * setHasBookmark(hasBookmark) - Sets whether the page is bookmarked or not.
                 **/
                 setHasBookmark: function(hasBookmark){
                   console.log('sgOneBookmarksModule:setHasBookmark()');

                   var bookmarkBadge = $('#bookmark-badge');
                   var bookmarkImage = bookmarkBadge.find("> img");

                   if (hasBookmark) {
                     bookmarkBadge.addClass("has-bookmark");
                     bookmarkBadge.attr("href", "sanfordapp://edit-bookmark");
                     bookmarkImage.attr("src", "icon_bookmark.svg");
                   } else {
                     bookmarkBadge.removeClass("has-bookmark");
                     bookmarkBadge.attr("href", "sanfordapp://add-bookmark");
                     bookmarkImage.attr("src", "icon_add_bookmark.png");
                   }
                 },

                /***
                 * setNotes(notes) - Sets the notes and updates UI.
                 **/
                 setNotes: function(notes){
                   console.log('sgOneBookmarksModule:setNotes()');
                   var notesStub = $('UserNotes');
                   notesStub.text(notes);

                   notesStub.append($("<div class='bottom-right-curl'></div>"));
                   notesStub.append($("<div class='bottom-border'></div>"));
                   notesStub.append($("<div class='top-border'></div>"));
                   notesStub.append($("<div class='left-border'></div>"));
                   notesStub.append($("<div class='right-border'></div>"));

                   var notesBadge = $('#notes-badge');
                   var notesImage = notesBadge.find("> img");

                   if (notes.trim().length > 0) {
                     $('body').addClass("has-notes");
                     notesStub.addClass("has-notes");
                     notesStub.show();

                     notesBadge.addClass("has-notes");
                     notesBadge.attr("href", "sanfordapp://edit-notes");
                     notesImage.attr("src", "icon_note.svg");

                     var scrollHeight = notesStub[0].scrollHeight;

                     notesStub.readmore({
                       moreLink: '<a class="notes-readmore-toggle" href="#" style="text-align: right;">more</a>',
                       lessLink: '<a class="notes-readmore-toggle" href="#" style="text-align: right">less</a>'
                     });

                      // if  there is overflow, then show readmore toggles
                      if (notesStub.height() + 20 < scrollHeight) {
                        try {
                          $('a.notes-readmore-toggle').show();
                        }catch(e) {
                          console.log("sgOneBookmarksModule::There was an error while showing toggles.");
                        }
                      } else {
                        try {
                          $('a.notes-readmore-toggle').hide();
                        }catch(e) {
                          console.log("sgOneBookmarksModule::There was an error while hiding toggles.");
                        }
                      }
                   } else {
                     $('body').removeClass("has-notes");
                     notesStub.removeClass("has-notes");
                     notesBadge.removeClass("has-notes");
                     notesStub.hide();
                     notesBadge.attr("href", "sanfordapp://add-notes");
                     notesImage.attr("src", "icon_add_notes.png");
                   }

                   var paperclip = $('#notes-paperclip');
                   if (paperclip.length <= 0) {
                     paperclip = $("<img id='notes-paperclip' src='icon_notes_paperclip.svg' alt='paperclip' />");
                     notesStub.before(paperclip);
                   }

                   // position the paperclip
                   try {
                     paperclip.position({
                       my: "left top",
                       at: "left+3 top-10",
                       of: notesStub,
                       collision: "none"
                     });
                   } catch (error) {
                     // silent prevents errors on the asp alert screens if the notes were visible on the content screen
                   }
                 },

               /***
                * updateUI() - Updates the UI according to current pageContext.
                *
                * Params set by operating environment:
                *   pageContext:  {hasBookmark:(bool), userNotes: (str)}
                **/
               updateUI: function() {
                 console.log('sgOneBookmarksModule:updateUI()');

                 var context = window.pageContext || {};

                 sgOneBookmarksModule.setHasBookmark(context.hasBookmark || false);
                 sgOneBookmarksModule.setNotes(context.userNotes || "");
               }
            };
          }();

          /**
           * PAGE HEADER MODULE
           **/
          window.sgOnePageHeaderModule = function(){
            return {
                  /***
                   * init - Initializes the module.
                   **/
                  init: function() {

                  console.log("sgOnePageHeaderModule:init()");

                  $(document).on('scroll', sgOnePageHeaderModule.pageHeader_onScroll);
                },
                /***
                 * pageHeader_onScroll() - handles minute scroll events
                 **/
                pageHeader_onScroll: function () {
                  // content page header should be fixed when scrollTop > 0
                  var scrollTop = $(document).scrollTop();
                  var atTop = scrollTop <= 0;
                  var pageHeader = $('body.sg-one-theme #content-page-header');

                  if (pageHeader) {
                    // check if offset
                    if (atTop) {
                      pageHeader.removeClass("fixed-page-header");
                    } else {
                      pageHeader.addClass("fixed-page-header");
                    }
                  }
                }
            };
          }();

          /**
           * TABLE OF CONTENTS MODULE
           **/
          window.sgOneTOCModule = function(){
            return {
                  /***
                   * registerTableOfContents() - Registers components.
                   **/
                  registerTableOfContents: function() {

                  console.log("sgOneTOCModule:registerTableOfContents()");

                  // clear prior registrations
                  sgOneTOCModule.unmount();

                  // build and attach the TOC to DOM
                  sgOneTOCModule.mount();

                  // activate image accessories
                  sgOneTOCModule.activateImages();
                },

                /***
                 * activateImages() - Attaches images to list items.
                 **/
                activateImages: function() {
                  // comments section
                  var commentsImage = $('body.sg-one-theme #toc-container ul li img.comments');

                  /* Comments */
                  if (commentsImage.length <= 0) {
                    commentsImage = $('<img></img>');
                    commentsImage.addClass('comments');
                    commentsImage.attr('src', './icon_comments.svg');
                    $('body.sg-one-theme #toc-container ul li:contains("Comments")').prepend(commentsImage);
                  }

                  // Dosing sections
                  var dosingImage = $('body.sg-one-theme #toc-container ul li img.usage-and-dosing');

                  /* Usage and Dosing */
                  if (dosingImage.length <= 0) {
                    dosingImage = $('<img></img>');
                    dosingImage.addClass('usage-and-dosing');
                    dosingImage.attr('src', './icon_dosage.svg');
                    $('body.sg-one-theme #toc-container ul li:contains("Usage & Dosing")').prepend(dosingImage);
                    $('body.sg-one-theme #toc-container ul li:contains("Usage and Dosing")').prepend(dosingImage);
                  }

                  // Adverse Effects sections
                  var adverseEffectsImage = $('body.sg-one-theme #toc-container ul li img.adverse-effects');

                  /* Adverse Effects */
                  if (adverseEffectsImage.length <= 0) {
                    adverseEffectsImage = $('<img></img>');
                    adverseEffectsImage.addClass('adverse-effects');
                    adverseEffectsImage.attr('src', './icon_adverse_effects.svg');
                    $('body.sg-one-theme #toc-container ul li:contains("Adverse Effects")').prepend(adverseEffectsImage);
                  }

                  // Spectrum sections
                  var spectrumImage = $('body.sg-one-theme #toc-container ul li img.spectrum');

                  /* Antimicrobial Spectrum */
                  if (spectrumImage.length <= 0) {
                    spectrumImage = $('<img></img>');
                    spectrumImage.addClass('spectrum');
                    spectrumImage.attr('src', './icon_spectrum_table.svg');
                    $('body.sg-one-theme #toc-container ul li:contains("Antimicrobial Spectrum")').prepend(spectrumImage);
                  }

                  // pharmacology section
                  var pharmaImage = $('body.sg-one-theme #toc-container ul li img.pharma');

                  /* Pharmacology */
                  if (pharmaImage.length <= 0) {
                    pharmaImage = $('<img></img>');
                    pharmaImage.addClass('spectrum');
                    pharmaImage.attr('src', './icon_pharmacology.svg');
                    $('body.sg-one-theme #toc-container ul li:contains("Pharmacology")').prepend(pharmaImage);
                  }

                  // Drug Interactions section
                  var interactionsImage = $('body.sg-one-theme #toc-container ul li img.drug-interactions');

                  /* Drug Interactions */
                  if (interactionsImage.length <= 0) {
                    interactionsImage = $('<img></img>');
                    interactionsImage.addClass('drug-interactions');
                    interactionsImage.attr('src', './icon_drug_interactions.png');
                    $('body.sg-one-theme #toc-container ul li:contains("Major Interactions")').prepend(interactionsImage);
                    $('body.sg-one-theme #toc-container ul li:contains("Major Drug Interactions")').prepend(interactionsImage);
                  }
                },

                /***
                 * mount() - Attaches components.
                 **/
                mount: function() {
                  var cboToc = $('<ul></ul>');
                  cboToc.attr("id","cboToc");

                  // append to guidetoc
                  var container = $("<div></div>");
                  container.attr("id", "toc-container")

                  // add toggle switch
                  var toggleSwitch = $('<a></a>');
                  toggleSwitch.attr("id", "toc-toggle-switch");
                  toggleSwitch.attr("href", "#");

                  toggleSwitch.html("Contents <span class='chevron-right'>&nbsp;</span>");

                  // add TOC components to DOM
                  container.append(cboToc);

                  $('GuideTOC').prepend(toggleSwitch);
                  toggleSwitch.after($('<a href="#" class="toc-close"></a>'));
                  $('GuideTOC').append(container);

                  $('body').off('click', 'GuideTOC');
                  $('body').on('click', 'GuideTOC', function() {
                    $('GuideTOC').toggleClass('active');
                    return false;
                  });

                  // for each h3, h2, h1 tag, add a tocId to it
                  $('h1, h2, h3').each(function(i) {
                      var newOpt = $('<li></li>');

                      var id = "toc_" + i;
                      var link_id = id + '_link';
                      $(this).attr("id", id);
                      newOpt.attr("id", link_id);
                      newOpt.text($(this).text());

                      // add nesting for h3's that follow h2'switch
                      if ($(this).is('h3') && $('#mobile-container-div h2').length > 0) {
                        var exceptions = ['Adverse Effects'];

                        var shouldIndent = exceptions.indexOf($(this).text().trim()) < 0;

                        if (shouldIndent) {
                          newOpt.addClass('toc-indent');
                        }
                      }

                      cboToc.append(newOpt);

                      // jump to header
                      $('body').off('click', '#'+link_id);
                      $('body').on('click', '#'+link_id, function(event) {

                        // prevent propagation of the event up to GuideTOC
                        event.stopPropagation();

                        $('GuideTOC').removeClass('active');

                        // if the element exists, then focus it
                        var jumpTargets = $('#'+id);
                        if (jumpTargets.length > 0) {
                          // can only jump to one; always choose first
                          sgOneTOCModule.jumpToElement(jumpTargets[0]);
                        }
                      });
                  });
                },

                /***
                 * setFocus() - Jumps to an element of interest.
                 **/
                jumpToElement: function(elem) {
                  var pageHeader = $('#content-page-header');
                  if (elem) {
                      elem.tabIndex = -1;
                      try {
                          // focus by moving scrollTop
                          var x = 0;
                          var y = 0;
                          var height = 0;

                          if (elem) {
                            // remember to wrap in jquery since it is a raw element
                            height = $(elem).outerHeight();
                          }
                          while (elem != null) {
                              x += elem.offsetLeft;
                              y += elem.offsetTop;
                              elem = elem.offsetParent;
                          }

                          // account for page header
                          if (pageHeader
                                && (pageHeader.css("position") === "fixed")
                                || y > 0) {
                            y -= pageHeader.outerHeight();

                            y -= height;
                          }

                          window.scrollTo(x, y);
                      } catch (e) {
                          //alert(" error occurred in setting focus");
                          elem.focus();
                      }
                  }
                },

                /***
                 * unmount() - Detaches components.
                 **/
                unmount: function() {
                  var toc = $('#cboToc');
                  var container = $('#toc-container');

                  // clear prior elements from DOM
                  if (toc) {
                    toc.remove();
                  }

                  if (container) {
                    container.remove();
                  }

                  $('GuideTOC').html('');
                }
            };
          }();

          /**
           * TOOLTIPS MODULE
           **/
          window.sgOneTooltipsModule = function(){
            return {
                  /***
                   * registerTooltips() - Registers components.
                   **/
                  registerTooltips: function() {

                  console.log("sgOneTooltipsModule:registerTooltips()");

                  // activate abbreviation tooltips
                  sgOneTooltipsModule.enableAbbreviationTooltips();
                },

                /***
                 * enableAbbreviationTooltips - Enables the abbreviation tooltips.
                 */
                enableAbbreviationTooltips: function() {
                    $(".abbreviation").eachAsync({delay: 100, bulk: 0, loop: function () {
                            $(this).off('click');
                            $(this).tooltip({
                              position: {
                                my: "center bottom+36",
                                at: "center bottom",
                                using: function( position, feedback ) {
                                  $( this ).css( position );
                                  $( "<div>" )
                                  .addClass( "arrow" )
                                  .addClass( feedback.vertical )
                                  .addClass( feedback.horizontal )
                                  .appendTo( this );
                                }
                              }
                            }).click(function (event) {
                              $(this).tooltip("enable");
                              event.stopPropagation();
                            });
                          }
                        });

                    $('#mobile-container-div').click(function() {
                      $(".abbreviation").tooltip("close");
                    });
                },
            };
          }();

          /**
           * VERSION INFO MODULE
           **/
          window.versionInfoModule = function(){
            return {
                  /***
                   * init - Initializes the module.
                   **/
                  init: function() {

                  console.log("versionInfoModule:init()");

                  let versionInfo = $('VersionInfo');
                  let modifiedTimestamp = versionInfo.attr("modified");

                  // format and display modified date
                  let formatted = new Date(modifiedTimestamp*1000)
                    .toLocaleDateString("en-US", {month:'short', day:'numeric', year:'numeric'});

                  $(versionInfo).html("Updated " + formatted);
                }
            };
          }();

          /**
           * SG ONE THEME MODULE
           **/
          sgOneThemeModule = function(){
        		return {
                  notesStub: null,
                  currentContentFontSize: 1,
                  cssElementsToModifyForContentTextSize: [
                    'body.sg-one-theme',
                    'body.sg-one-theme h2',
                    'body.sg-one-theme h3:not(.recommended-spectrum):not(.active-spectrum)',
                    'body.sg-one-theme VersionInfo',
                    'body.sg-one-theme UserNotes'
                  ],

          		    /***
                   * init() - Initializes the module.
                   **/
                  init: function(){
                    console.log('sgOneThemeModule:init()');

                    this.addStyles();

                    this.applyTheme();

                    window.ontouchend = this.scaleHeaders;
                    this.scaleHeaders();
                  },

                  scaleHeaders: function() {
                    var zoomedWidth = document.body.offsetWidth / window.visualViewport.scale;
                    $('#content-page-header').css('width', zoomedWidth);
                    $('h1, h2, h3').css('width', zoomedWidth);
                  },

                  applyTheme: function(){
                    console.log('sgOneThemeModule:applyTheme()');
                    $('body').addClass('sg-one-theme');

                    // initialize bookmarks module
                    // for SG Collection since older versions didn't handle
                    // initialization in the native VCs.
                    var needsAutoInitialize = window.location.pathname.includes('com.sanfordguide.collection');
                    if (needsAutoInitialize) {
                      sgOneBookmarksModule.init();
                    }

                    // register toc
                    window.buildToc = window.registerTableOfContents = sgOneTOCModule.registerTableOfContents;
                    registerTableOfContents();

                    // register back-to-top
                    window.registerBackToTop = sgOneBackToTopModule.registerBackToTop;
                    registerBackToTop();

                    // initialize version info module
                    versionInfoModule.init();

                    // register the custom abbreviation tooltips
                    window.registerTooltips = sgOneTooltipsModule.registerTooltips;
                    registerTooltips();

                    // handle fixed page header
                    sgOnePageHeaderModule.init();
                  },

                  addStyles: function(){
                    var linkedCss = $('link[href^="./sg-one-theme.css"],link[href^="sg-one-theme.css"]');

                    if( linkedCss.length <= 0 ) {
                      var css = $('<link rel="stylesheet" href="./sg-one-theme.css"></link>');
                      $('head').append(css);
                    }
                  },


                  resizeContent: function(newContentSize) {
                    if (newContentSize > this.currentContentFontSize) {
                      this.scaleContentFontSizesByInt(5);
                      this.currentContentFontSize++;
                    } else if (newContentSize < this.currentContentFontSize) {
                      this.scaleContentFontSizesByInt(-5);
                      this.currentContentFontSize--;
                    }

                    if (newContentSize !== this.currentContentFontSize) {
                      this.resizeContent(newContentSize);
                    }
                  },

                  scaleContentFontSizesByInt: function(scalingIncrement) {
                    for (let cssSelector of this.cssElementsToModifyForContentTextSize) {
                      document.querySelectorAll(cssSelector).forEach(
                        element => element.style.fontSize = (parseFloat(window.getComputedStyle(element, null).getPropertyValue('font-size'))+scalingIncrement)+ "px");
                    }
                  }
        		    };
        	}();

          sgOneThemeModule.init();
    });

})(jQuery);
