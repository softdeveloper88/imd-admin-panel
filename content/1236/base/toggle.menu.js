$(document).ready(function () {
    $(document).on('click', '.toggleMenu', function() {
        $(this).next('div').toggleClass('expanded');
    });
});