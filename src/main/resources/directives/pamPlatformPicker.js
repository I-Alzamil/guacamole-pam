/**
 * Picker of the platform of a connection, in place of a drop-down: a button
 * showing the platform chosen, opening a list grouped by type, with a search
 * on top. Driven by mouse or keyboard (arrows, Enter, Escape). The model is
 * the platform identifier as a string; null means the password is stored
 * only.
 */
angular.module('guacPam').directive('pamPlatformPicker', ['$document', '$timeout', '$translate', 'guacNotification',
        'pamService', function pamPlatformPicker($document, $timeout, $translate, guacNotification, pamService) {

    return {
        restrict    : 'E',
        scope       : {
            model    : '=',
            disabled : '<',
            fieldId  : '@'
        },
        templateUrl : 'app/ext/pam/templates/pamPlatformPicker.html',
        link        : function linkPlatformPicker($scope, $element) {

            /**
             * Platforms to choose from, as {id, label, type}, sorted by type
             * then name.
             */
            var platforms = [];

            /**
             * The choice of storing the password only.
             */
            var STORED_ONLY = { id : '', label : $translate.instant('PAM.FIELD_OPTION_STORED_ONLY'), type : '' };

            /**
             * Shown until the platforms are loaded, rather than a platform
             * or "stored only", which could be wrong.
             */
            var LOADING = { id : null, label : $translate.instant('PAM.INFO_LOADING'), type : '' };

            /**
             * Whether the platforms are loaded.
             */
            $scope.loaded = false;

            $scope.open = false;
            $scope.search = { text : '' };

            /**
             * What the list shows: group headers and the options matching
             * the search, as {group} or {option}.
             */
            $scope.rows = [];

            /**
             * The options shown, in order, for the keyboard.
             */
            var options = [];

            /**
             * Index in options of the option the keyboard is on.
             */
            $scope.active = 0;

            var current = function current() {
                return $scope.model ? String($scope.model) : '';
            };

            $scope.selected = function selected() {
                if (!$scope.loaded)
                    return LOADING;
                for (var i = 0; i < platforms.length; i++) {
                    if (platforms[i].id === current())
                        return platforms[i];
                }
                return STORED_ONLY;
            };

            $scope.isSelected = function isSelected(option) {
                return option.id === current();
            };

            $scope.isActive = function isActive(option) {
                return options[$scope.active] === option;
            };

            var update = function update() {

                var text = $scope.search.text.trim().toLowerCase();
                var rows = [];
                var shown = [];
                var group = null;

                if (!text) {
                    rows.push({ option : STORED_ONLY });
                    shown.push(STORED_ONLY);
                }

                angular.forEach(platforms, function addPlatform(platform) {
                    if (text && (platform.label + ' ' + platform.type).toLowerCase().indexOf(text) === -1)
                        return;
                    if (platform.type !== group) {
                        group = platform.type;
                        rows.push({ group : group || '?' });
                    }
                    rows.push({ option : platform });
                    shown.push(platform);
                });

                $scope.rows = rows;
                options = shown;
                $scope.active = Math.max(0, options.indexOf($scope.selected()));
                $scope.empty = !shown.length;

            };

            $scope.$watch('search.text', update);

            var scrollToActive = function scrollToActive() {
                $timeout(function scrollActive() {
                    var active = $element[0].querySelector('.pam-picker-option.active');
                    if (active)
                        active.scrollIntoView({ block : 'nearest' });
                }, 0, false);
            };

            var closeOnOutsideClick = function closeOnOutsideClick(event) {
                if (!$element[0].contains(event.target))
                    $scope.$apply($scope.close);
            };

            $scope.toggle = function toggle() {
                if ($scope.open) {
                    $scope.close();
                    return;
                }
                if ($scope.disabled || !$scope.loaded)
                    return;
                $scope.open = true;
                $scope.search.text = '';
                update();
                $document.on('mousedown', closeOnOutsideClick);
                $timeout(function focusSearch() {
                    var search = $element[0].querySelector('.pam-picker-search');
                    if (search)
                        search.focus();
                    scrollToActive();
                }, 0, false);
            };

            $scope.close = function close() {
                $scope.open = false;
                $document.off('mousedown', closeOnOutsideClick);
            };

            $scope.choose = function choose(option) {
                $scope.model = option.id || null;
                $scope.close();
                $element[0].querySelector('.pam-picker-current').focus();
            };

            $scope.keydown = function keydown(event) {
                switch (event.key) {
                    case 'ArrowDown':
                        $scope.active = Math.min(options.length - 1, $scope.active + 1);
                        scrollToActive();
                        break;
                    case 'ArrowUp':
                        $scope.active = Math.max(0, $scope.active - 1);
                        scrollToActive();
                        break;
                    case 'Enter':
                        if (options[$scope.active])
                            $scope.choose(options[$scope.active]);
                        break;
                    case 'Escape':
                        $scope.close();
                        $element[0].querySelector('.pam-picker-current').focus();
                        break;
                    case 'Tab':
                        $scope.close();
                        return;
                    default:
                        return;
                }
                event.preventDefault();
            };

            // Arrows open the list, as for a drop-down
            $scope.buttonKeydown = function buttonKeydown(event) {
                if (!$scope.open && (event.key === 'ArrowDown' || event.key === 'ArrowUp')) {
                    event.preventDefault();
                    $scope.toggle();
                }
            };

            $scope.$on('$destroy', function pickerDestroyed() {
                $document.off('mousedown', closeOnOutsideClick);
            });

            pamService.getPlatforms().then(function platformsRetrieved(retrieved) {

                var loaded = [];
                var found = !current();

                angular.forEach(retrieved, function addPlatform(platform) {
                    var id = String(platform.id);
                    found = found || id === current();
                    loaded.push({
                        id    : id,
                        label : platform.name,
                        type  : $translate.instant('PAM.TYPE_' + platform.type.toUpperCase())
                    });
                });

                // Keep a stale assignment visible rather than silently clearing it
                if (!found)
                    loaded.push({ id : current(), label : '#' + current() + ' (missing)', type : '' });

                loaded.sort(function byTypeThenName(a, b) {
                    return a.type.localeCompare(b.type) || a.label.localeCompare(b.label);
                });

                platforms = loaded;
                $scope.loaded = true;
                update();

            }, guacNotification.SHOW_REQUEST_ERROR);

        }
    };

}]);
