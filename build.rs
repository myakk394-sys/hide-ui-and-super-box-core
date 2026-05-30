fn main() {
    #[cfg(target_os = "windows")]
    {
        embed_resource::compile("wintun/super_box.rc", embed_resource::NONE);
    }
}
