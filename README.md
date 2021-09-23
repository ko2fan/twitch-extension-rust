# twitch-extension-rust
This is a twitch extension backend written in rust for use with the colour changing example from twitch

# Usage
This is designed to be used with Twitch Developer Rig. It only contains the backend, you will need to use the front end from https://github.com/twitchdev/extension-getting-started
You will also need to have created an extension.

Start the backend with
`cargo run -- -c <client id> -s <secret> -o <channel id>`

You should be able to get these details from the Twitch Developer Rig.
