/**
 * Shows only the "Password management" sections of the connection editor
 * that apply: the policy section and the section of the platform's type
 * only for managed connections, and the setting showing the password to
 * holders, with its security warning, only for connections other than
 * Accounts (whose password is always shown). Placed next to the connection
 * editor's forms by templates/pamManagementSections.html, and uses that
 * editor's scope.
 */
angular.module('guacPam').directive('pamManagementSections', ['$injector', function pamManagementSections($injector) {

    var $compile   = $injector.get('$compile');
    var pamService = $injector.get('pamService');

    /**
     * Class prefix of the per-type sections ("form-pam-type-ssh", ...).
     */
    var TYPE_FORM_PREFIX = 'form-pam-type-';

    var HIDDEN_CLASS = 'pam-hidden';

    var REVEAL_FIELD = 'labeled-field-pam-reveal-password';

    var WARNING_CLASS = 'pam-field-warning';

    return {
        restrict : 'E',
        link     : function linkManagementSections($scope, $element) {

            // The connection itself may still be loading (when editing an
            // existing one), so only the editor's layout is checked here
            var parent = $element[0].parentNode;
            var attributes = parent && parent.querySelector('.attributes');
            if (!attributes)
                return;

            /**
             * Type of each platform, by identifier.
             */
            var platformTypes = {};

            var apply = function apply() {

                // Hide everything conditional until the connection is known
                var connection = $scope.connection || {};
                var platformId = connection.attributes && connection.attributes['pam-platform'];
                var managed = !!platformId;
                var type = managed ? platformTypes[platformId] : null;

                angular.forEach(attributes.querySelectorAll('.form'), function toggleForm(form) {

                    var visible = true;
                    var classes = form.className.split(/\s+/);

                    angular.forEach(classes, function checkClass(name) {
                        if (name === 'form-pam-policy')
                            visible = managed;
                        else if (name.indexOf(TYPE_FORM_PREFIX) === 0)
                            visible = managed && name.substring(TYPE_FORM_PREFIX.length) === type;
                    });

                    angular.element(form).toggleClass(HIDDEN_CLASS, !visible);

                });

                // Next to the checkbox, in the block Guacamole wraps it in
                var reveal = attributes.querySelector('.' + REVEAL_FIELD);
                var cell = reveal && (reveal.querySelector('.form-field .checkbox-field')
                        || reveal.querySelector('.form-field'));
                if (cell) {
                    angular.element(reveal).toggleClass(HIDDEN_CLASS, connection.protocol === 'pam-account');
                    // Shown on hover, or when clicked (focused)
                    if (!cell.querySelector('.' + WARNING_CLASS))
                        cell.appendChild($compile('<span class="' + WARNING_CLASS + '" tabindex="0" role="note"'
                                + ' aria-label="{{ \'PAM.HELP_REVEAL_PASSWORD\' | translate }}">'
                                + '<span aria-hidden="true">&#9888; {{ \'PAM.INFO_SECURITY_NOTE\' | translate }}</span>'
                                + '<span class="pam-field-warning-text" aria-hidden="true">'
                                + '{{ \'PAM.HELP_REVEAL_PASSWORD\' | translate }}</span></span>')($scope)[0]);
                }

            };

            pamService.getPlatforms().then(function platformsRetrieved(platforms) {
                angular.forEach(platforms, function addPlatform(platform) {
                    platformTypes[String(platform.id)] = platform.type;
                });
                apply();
            });

            $scope.$watchGroup(['connection.protocol', 'connection.attributes["pam-platform"]'], apply);

            // Forms are rendered asynchronously; apply again when they appear
            var observer = new MutationObserver(apply);
            observer.observe(attributes, { childList : true, subtree : true });
            $scope.$on('$destroy', function sectionsDestroyed() {
                observer.disconnect();
            });

        }
    };

}]);
