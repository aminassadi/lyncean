#include "input_parser.h"
#include <stdlib.h>

std::tuple<int, std::string, std::vector<std::string>> InputParser::get_input_parameters(int argc, ARGV &argv)
{
    argparse::ArgumentParser parser("lyncean");
    register_pid(parser);
    register_command(parser);
    apply_parser(parser, argc, argv);
    auto optionalPid = extract_pid(parser);
    auto optionalCmd = extract_command(parser);
    check_inputs(parser, optionalPid, optionalCmd);
    auto pid = get_pid_value(optionalPid);
    auto [command, params] = separate_command_params(optionalCmd);
    return {pid, command, params};
}

void InputParser::register_pid(Parser &parser)
{
    parser.add_argument("--pid")
        .default_value(0)
        .help("whcih process id to watching.")
        .action([](const std::string &value)
                {
            try 
            {
                auto tmp = std::stoi(value);
                if(tmp < 0)
                {
                    throw std::invalid_argument("");
                }
                return tmp;
            } 
            catch (const std::invalid_argument &) 
            {
                std::cerr << "Error: --pid requires an integer value greater than zero." << std::endl;
                exit(EXIT_FAILURE);
            } 
            catch (const std::out_of_range &) 
            {
                std::cerr << "Error: --pid value is out of range." << std::endl;
                exit(EXIT_FAILURE);
            } });
}

void InputParser::register_command(Parser &parser)
{
    parser.add_argument("--command")
        .default_value(std::vector<std::string>({"empty"}))
        .help("The command to execute")
        .remaining();
}

void InputParser::apply_parser(Parser &parser, int argc, ARGV &argv)
{
    try
    {
        parser.parse_args(argc, argv);
    }
    catch (const std::runtime_error &err)
    {
        std::stringstream msg;
        msg << "Error parsing arguments: " << err.what() << std::endl;
        msg << parser;
        throw std::invalid_argument(msg.str());
    }
}

std::optional<int> InputParser::extract_pid(Parser &parser)
{
    if (parser.is_used("--pid"))
    {
        auto pid = parser.get<int>("pid");
        if (pid)
        {
            return pid;
        }
    }
    return std::nullopt;
}

std::optional<std::string> InputParser::extract_command(Parser &parser)
{
    if (parser.is_used("--command"))
    {
        std::string command{};
        auto tmp = parser.get<std::vector<std::string>>("command");
        for (auto itr = tmp.begin(); itr != tmp.end();)
        {
            command += *itr;
            ++itr;
            if (itr == tmp.end())
                break;
            command += " "s;
        }

        if (command != "empty"s)
        {
            return command;
        }
    }
    return std::nullopt;
}

void InputParser::check_inputs(Parser &parser, std::optional<int> pid, std::optional<std::string> cmd)
{
    if (!pid && !cmd)
    {
        std::stringstream msg;
        msg << "Error: You must specify exactly one of --pid or --command." << std::endl;
        msg << parser;
        throw std::invalid_argument(msg.str());
    }
}

std::tuple<std::string, std::vector<std::string>> InputParser::separate_command_params(std::optional<std::string> cmd)
{
    std::string command{};
    std::vector<std::string> params{};
    std::string tmpParams{};

    if (cmd.has_value())
    {
        auto &tmp = cmd.value();
        auto firstSpace = tmp.find(' ');
        command = tmp.substr(0, firstSpace);
        size_t rest = tmp.find_first_not_of(' ', firstSpace);
        if (rest != std::string::npos)
        {
            tmpParams = tmp.substr(rest);
        }
    }

    size_t pos = 0;
    std::string token;
    while ((pos = tmpParams.find(' ')) != std::string::npos) 
    {
        token = tmpParams.substr(0, pos);
        if (!token.empty()) {
            params.push_back(token);
        }
        tmpParams.erase(0, pos + 1);
    }
    if (!tmpParams.empty()) {
        params.push_back(tmpParams);
    }

    return {command, params};
}

int InputParser::get_pid_value(std::optional<int> pid)
{
    if(pid)
    {
        return pid.value();
    }
    return 0;
}
