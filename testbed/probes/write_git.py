# **/.git is protected: repository configuration stays out of reach of repos/**.
open("repos/alpha/.git/config", "a").write("\n")
