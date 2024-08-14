
struct setting
{
    int target_pid;
    bool follow_forks;
};

class service_locator
{
private:
    static setting _setting;

public:
    service_locator() = default;
    virtual ~service_locator() = 0;
    static void provide_setting(setting s) { _setting = s; }
    const setting& get_setting() {return _setting;}
};

setting service_locator::_setting = setting();