import plotly.graph_objects as go

def create_risk_gauge(score: float) -> go.Figure:
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Composite Risk Score"},
        gauge={
            'axis': {'range': [0, 1]},
            'bar': {'color': "darkblue"},
            'steps': [
                {'range': [0, 0.4], 'color': "lightgreen"},
                {'range': [0.4, 0.7], 'color': "yellow"},
                {'range': [0.7, 1.0], 'color': "salmon"},
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 0.9
            }
        }
    ))
    return fig
