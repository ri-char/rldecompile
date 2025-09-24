import asyncio
import os
from concurrent.futures import ProcessPoolExecutor

import fastapi
from hypercorn.asyncio import serve
from hypercorn.config import Config
from hypercorn.middleware import ProxyFixMiddleware
from loguru import logger
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace.status import StatusCode
from pydantic import BaseModel

from eval import ExeBenchProblem, OjProblem, client
from lib.code_analysis import (
    c_parser,
    calculate_TSED,
    check_is_function_definition,
    find_error_node_counts,
    get_argument_type,
)
from lib.utils import init_log

resource = Resource.create(attributes={SERVICE_NAME: "rl-reward-server"})

tracerProvider = TracerProvider(resource=resource)
processor = BatchSpanProcessor(OTLPSpanExporter(endpoint="http://192.168.5.187:4317"))
tracerProvider.add_span_processor(processor)
trace.set_tracer_provider(tracerProvider)


# Get a tracer instance
tracer = trace.get_tracer(__name__)


class SampleArguments(BaseModel):
    completion: str
    problem_id: str


class RewardArguments(BaseModel):
    samples: list[SampleArguments]
    key: str


app = fastapi.FastAPI()
executor = ProcessPoolExecutor(max_workers=8)


@app.get("/")
async def root():
    return {"status": "ok"}


REWARD_GRAMMAR_WEIGHT = 1
REWARD_SINGLE_FUNCTION_WEIGHT = 1
REWARD_TSED_WEIGHT = 1
REWARD_COUNT_ARGS_WEIGHT = 1
REWARD_ARGS_TYPE_WEIGHT = 1
REWARD_COMPILE_SUCCESS_WEIGHT = 5
REWARD_TEST_SUCCESS_WEIGHT = 5


@app.post("/reward")
async def reward_api(args: RewardArguments, response: fastapi.Response):
    if args.key != os.environ["RL_SERVER_KEY"]:
        response.status_code = fastapi.status.HTTP_401_UNAUTHORIZED
        return {}

    tasks = [reward_func(sample) for sample in args.samples]
    try:
        result = await asyncio.gather(*tasks)
        return result
    except Exception:
        logger.exception("reward error")
        response.status_code = fastapi.status.HTTP_500_INTERNAL_SERVER_ERROR
        return {}


async def reward_func(args: SampleArguments) -> float:
    with tracer.start_as_current_span("reward_function") as span:
        span.set_attribute("problem_id", args.problem_id)
        span.set_attribute("completion", args.completion)
        # part 1: code grammar
        with tracer.start_as_current_span("check_grammar") as span_inner:
            input_code = args.completion.encode()
            cst_tree = c_parser.parse(input_code)
            reward_grammar = -find_error_node_counts(cst_tree.root_node)
            reward_single_function = int(
                check_is_function_definition(cst_tree.root_node)
            )
            span_inner.set_attribute("reward_single_function", reward_single_function)
            span_inner.set_attribute("reward_grammar", reward_grammar)

        span.set_attribute("reward_single_function", reward_single_function)
        span.set_attribute("reward_grammar", reward_grammar)
        if reward_grammar != 0 or reward_single_function != 1:
            total_reward = (
                REWARD_GRAMMAR_WEIGHT * reward_grammar
                + REWARD_SINGLE_FUNCTION_WEIGHT * reward_single_function
            )
            return float(
                REWARD_GRAMMAR_WEIGHT * reward_grammar
                + REWARD_SINGLE_FUNCTION_WEIGHT * reward_single_function
            )

        # load problem
        with tracer.start_as_current_span("load_problem") as span_inner:
            row = await client["exebench"].find_one(
                {"id": args.problem_id}, projection={"_id": 0}
            )
            if row is not None:
                problem = ExeBenchProblem.model_validate(row)
            else:
                row = await client["oj_problems"].find_one(
                    {"id": args.problem_id}, projection={"_id": 0}
                )
                if row is None:
                    logger.warning("not found problem " + args.problem_id)
                    raise fastapi.HTTPException(
                        status_code=404, detail="Problem not found"
                    )
                problem = OjProblem.model_validate(row)
            ground_truth_code = (
                problem.code if isinstance(problem, OjProblem) else problem.func_def
            )

        # part 2: Tree Similarity of Edit Distance
        # https://github.com/Etamin/TSED https://arxiv.org/abs/2404.08817
        reward_tsed = 0
        with tracer.start_as_current_span("ast_diff") as span_inner:
            try:
                reward_tsed = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        executor,
                        calculate_TSED,
                        args.completion,
                        ground_truth_code,
                        1,
                        1,
                        10,
                    ),
                    timeout=10,
                )
                span_inner.set_attribute("reward_tsed", reward_tsed)
                span.set_attribute("reward_tsed", reward_tsed)
            except asyncio.TimeoutError:
                span_inner.set_status(StatusCode.ERROR)
                span_inner.set_attribute("reward_tsed", "timeout")
                span.set_attribute("reward_tsed", "timeout")

        # part 3: number of arguments
        reward_count_args = 0
        reward_args_type = 0
        with tracer.start_as_current_span("check_number_arg") as span_inner:
            try:
                arguments = get_argument_type(cst_tree.root_node, input_code)
                ground_truth_code_node = c_parser.parse(ground_truth_code.encode())
                real_arguments = get_argument_type(
                    ground_truth_code_node.root_node, ground_truth_code.encode()
                )
                reward_count_args = int(len(arguments) == len(real_arguments))
                span_inner.set_attributes(
                    {
                        "arguments": len(arguments),
                        "real_arguments": len(real_arguments),
                        "reward_count_args": reward_count_args,
                    }
                )
                span.set_attribute("reward_count_args", reward_count_args)

                if reward_count_args != 1:
                    total_reward = (
                        REWARD_GRAMMAR_WEIGHT * reward_grammar
                        + REWARD_SINGLE_FUNCTION_WEIGHT * reward_single_function
                    )
                    return float(total_reward)

                for t1, t2 in zip(arguments, real_arguments):
                    if t1.replace(" ", "") == t2.replace(" ", ""):
                        reward_args_type += 1
                reward_args_type /= len(arguments)
                span_inner.set_attribute("reward_args_type", reward_args_type)
                span.set_attribute("reward_args_type", reward_args_type)
            except KeyboardInterrupt:
                raise
            except:  # noqa: E722
                logger.exception("get arguments type error")

        # part 4: run test
        reward_compile_success = 0
        reward_test_success = 0
        with tracer.start_as_current_span("compile_and_test") as span_inner:
            if isinstance(problem, ExeBenchProblem):
                problem.func_def = args.completion
                try:
                    (
                        reward_compile_success,
                        reward_test_success,
                    ) = await problem.run_tests_reward(tracer)
                    span_inner.set_attributes(
                        {
                            "reward_compile_success": reward_compile_success,
                            "reward_test_success": reward_test_success,
                        }
                    )
                    span.set_attributes(
                        {
                            "reward_compile_success": reward_compile_success,
                            "reward_test_success": reward_test_success,
                        }
                    )
                except (
                    RuntimeError,
                    asyncio.TimeoutError,
                    asyncio.exceptions.CancelledError,
                ):
                    logger.warning(
                        f"Runtime error during test for problem: {args.problem_id}"
                    )
        total_reward = (
            REWARD_GRAMMAR_WEIGHT * reward_grammar
            + REWARD_TSED_WEIGHT * reward_tsed
            + REWARD_SINGLE_FUNCTION_WEIGHT * reward_single_function
            + REWARD_COUNT_ARGS_WEIGHT * reward_count_args
            + REWARD_ARGS_TYPE_WEIGHT * reward_args_type
            + REWARD_COMPILE_SUCCESS_WEIGHT * reward_compile_success
            + REWARD_TEST_SUCCESS_WEIGHT * reward_test_success
        )
        span.set_attribute("total_reward", total_reward)
        return total_reward


if __name__ == "__main__":
    config = Config()
    config.bind = ["0.0.0.0:8085"]
    config.graceful_timeout = 1
    init_log()

    FastAPIInstrumentor.instrument_app(app)
    fixed_app = ProxyFixMiddleware(app, mode="legacy", trusted_hops=1)  # type: ignore
    asyncio.run(serve(fixed_app, config))
