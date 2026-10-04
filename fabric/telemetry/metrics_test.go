package telemetry

import (
	"context"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestOperationMetricsHaveFiniteDimensionsAndCountActualEndOnce(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	meter := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer meter.Shutdown(context.Background())
	tracer := sdktrace.NewTracerProvider()
	defer tracer.Shutdown(context.Background())
	p, err := New(Config{Tracer: tracer.Tracer("pagnet/fabric"), Meter: meter.Meter("pagnet/fabric")})
	if err != nil {
		t.Fatal(err)
	}
	_, span := p.Start(context.Background(), Specification{Name: "pagnet.invoke", InvocationID: "private-high-cardinality-id"})
	var before metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &before); err != nil {
		t.Fatal(err)
	}
	for _, scope := range before.ScopeMetrics {
		if len(scope.Metrics) != 0 {
			t.Fatal("active operation was counted before termination")
		}
	}
	span.End("completed")
	span.End("failed")
	var after metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &after); err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, scope := range after.ScopeMetrics {
		for _, instrument := range scope.Metrics {
			switch data := instrument.Data.(type) {
			case metricdata.Sum[int64]:
				if len(data.DataPoints) != 1 || data.DataPoints[0].Value != 1 {
					t.Fatal(data)
				}
				if data.DataPoints[0].Attributes.Len() != 2 {
					t.Fatal("unbounded metric dimensions")
				}
				seen++
			case metricdata.Histogram[float64]:
				if len(data.DataPoints) != 1 || data.DataPoints[0].Count != 1 || data.DataPoints[0].Sum < 0 {
					t.Fatal(data)
				}
				if data.DataPoints[0].Attributes.Len() != 2 {
					t.Fatal("unbounded metric dimensions")
				}
				seen++
			default:
				t.Fatal("unexpected metric", instrument.Name)
			}
		}
	}
	if seen != 2 {
		t.Fatal("missing real OpenTelemetry instruments", seen)
	}
}
