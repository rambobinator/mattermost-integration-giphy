# -*- coding: utf-8 -*-
import os

# username the bot posts as
USERNAME = os.environ.get('USERNAME', 'giphy')

# display picture the bot posts with
ICON_URL = os.environ.get('ICON_URL', 'https://avatars0.githubusercontent.com/u/3588525?v=3&s=200')

# the maximum parental rating of gifs posted
RATING = os.environ.get('RATING', 'pg')

# scheme to be used for the gif url return to mattermost
SCHEME = os.environ.get('SCHEME', 'https')

# the is a public beta key from giphy api
GIPHY_API_KEY = os.environ.get('GIPHY_API_KEY', 'dc6zaTOxFJmzC')

# the Mattemost token generated when you created your outgoing webhook
MATTERMOST_GIPHY_TOKEN = os.environ.get('MATTERMOST_GIPHY_TOKEN', None)

# the Mattemost token generated when you created your incomming webhook
MATTERMOST_GIPHY_IN_TOKEN = os.environ.get('MATTERMOST_GIPHY_IN_TOKEN', None)

# the number of suggested gif
GIPHY_SEARCH_LIMIT = os.environ.get('GIPHY_SEARCH_LIMIT', 5)
