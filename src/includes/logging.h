// Well, thanks ChatGPT for writing this clean logger for me.
#ifndef LOGGING_H
#define LOGGING_H

#include <chrono>
#include <string>
#include <unordered_map>
#include <vector>

// print for debug. Easily turn on/off by defining _DEBUG
#ifdef _DEBUG
#define DEBUG_PRINT(s) std::cout << s << std::endl;
#endif

#ifdef _BENCHMARK
#define DEBUG_PRINT(s) ; // do nothing
#endif

#define BENCH_PRINT(s) std::cout << s << std::endl;
#define PRINT_BAR                                                              \
  BENCH_PRINT("==============================================================" \
              "================");

constexpr std::size_t WARMUP_ITERATIONS = 3;

// predefine some name for logging
#define CORE_TIME "Core"
#define FST_DIM_PREP "First dim prep"
#define FST_DIM_TIME "First dim"
#define OTHER_DIM_TIME "Other dim"
#define EXPAND_TIME "Expand"
#define APPLY_GALOIS "Apply Galois"
#define CONVERT_TIME "Convert"
#define CONVERT_EXTERN "Convert external product"
#define SERVER_TOT_TIME "Server total"
#define CLIENT_TOT_TIME "Client total"
#define OTHER_DIM_ADD_SUB "Other dim add/sub"
#define OTHER_DIM_MUX_EXTERN "External product in other dim"
#define DECOMP_RLWE_TIME "Decomp RLWE (including conversion)"
#define EXTERN_PROD_MAT_MULT_TIME "External product mat mult (including conversion)"
#define FST_NTT_TIME "First dim NTT"
#define EXTERN_NTT_TIME "External NTT"
#define OTHER_DIM_INTT "Other dim INTT"
#define EXTERN_COMPOSE "external compose"
#define EXTERN_DECOMP "external decompose"
#define MOD_SWITCH "Modulus switching"

#define RIGHT_SHIFT_TIME "Right shift"
#define FST_DELEY_MOD_TIME "First dim delay mod"

// Hierarchical structure for pretty result
// Map structure: Parent -> Children
const std::unordered_map<std::string, std::vector<std::string>> LOG_HIERARCHY = {
    {SERVER_TOT_TIME, {EXPAND_TIME, CONVERT_TIME, FST_DIM_TIME, OTHER_DIM_TIME, MOD_SWITCH}},
    {EXPAND_TIME, {APPLY_GALOIS}},
    {CONVERT_TIME, {CONVERT_EXTERN}},
    {FST_DIM_TIME, {CORE_TIME, FST_DIM_PREP, FST_DELEY_MOD_TIME, FST_NTT_TIME}},
    {OTHER_DIM_TIME, {OTHER_DIM_MUX_EXTERN, OTHER_DIM_INTT, OTHER_DIM_ADD_SUB}},
    {OTHER_DIM_MUX_EXTERN, {DECOMP_RLWE_TIME, EXTERN_PROD_MAT_MULT_TIME}},
    {DECOMP_RLWE_TIME, {EXTERN_COMPOSE, EXTERN_NTT_TIME, RIGHT_SHIFT_TIME, EXTERN_DECOMP}}
};



class TimerLogger {
private:
  // Stores start times of active sections
    std::unordered_map<std::string, std::chrono::high_resolution_clock::time_point> startTimes;

  // Stores all timing results for multiple experiments
  std::vector<std::unordered_map<std::string, double>> experimentRecords;

  // Stores timing data for the current experiment
  std::unordered_map<std::string, double> currentExperiment;

  // Private constructor for Singleton
  TimerLogger() = default;

  // Recursive helper for pretty printing
  void prettyPrintHelper(
      const std::string &section, const std::string &prefix, bool isLast,
      const std::unordered_map<std::string, double> &avgTimes) const;

public:
  // Singleton instance
  static TimerLogger &getInstance();

  // Start logging time for a section
  void start(const std::string &sectionName);

  // Stop logging time for a section
  void end(const std::string &sectionName);

  // End the current experiment and start a new one
  void endExperiment();

  // Print results for specific experiment. -1 to print all experiments
  void printResults(int expId = -1);

  // Compute and print average time across experiments
  void printAverageResults();

  double getAvgTime(const std::string &sectionName);

  // Pretty print hierarchical results
  void prettyPrint();

  void cleanup();

  // Prevent copying
  TimerLogger(const TimerLogger &) = delete;
  TimerLogger &operator=(const TimerLogger &) = delete;
};

// Macros for easy time logging
#define TIME_START(sec) TimerLogger::getInstance().start(sec)
#define TIME_END(sec) TimerLogger::getInstance().end(sec)
#define END_EXPERIMENT() TimerLogger::getInstance().endExperiment()
#define PRINT_RESULTS(expId) TimerLogger::getInstance().printResults(expId)
#define PRINT_AVERAGE_RESULTS() TimerLogger::getInstance().printAverageResults()
#define GET_AVG_TIME(sec) TimerLogger::getInstance().getAvgTime(sec)
#define PRETTY_PRINT() TimerLogger::getInstance().prettyPrint()
#define CLEAN_TIMER() TimerLogger::getInstance().cleanup()

#endif // LOGGER_H
