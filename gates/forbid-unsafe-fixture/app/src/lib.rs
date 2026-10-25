// Members (mac/rawid/inc/tgt/pm) compile on their own; `outside` is excluded
// from the workspace, so it compiles only as this dependency.
pub fn go() { outside::run(); }
