"""Interactive Network Security and Asset Visibility Dashboard."""

import json
from collections import Counter
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from network_asset_visibility.dashboard_data import (
    RISK_LEVELS,
    get_asset_risk_ranking,
    get_dashboard_summary,
    get_prioritized_findings,
    get_risk_distribution,
    get_severity_distribution,
    load_security_report,
)


PROJECT_ROOT = Path(__file__).resolve().parent
REPORT_PATH = PROJECT_ROOT / "security-report.json"
ICON_PATH = PROJECT_ROOT / "assets" / "security-icon.png"

RISK_COLORS = {
    "critical": "#DC2626",
    "high": "#F97316",
    "medium": "#EAB308",
    "low": "#22C55E",
}

FINDING_COLUMNS = [
    "asset_id",
    "hostname",
    "rule_id",
    "title",
    "severity",
    "asset_criticality",
    "risk_score",
    "risk_priority",
]


st.set_page_config(
    page_title="Network Security Dashboard",
    page_icon=str(ICON_PATH),
    layout="wide",
    initial_sidebar_state="expanded",
)


def distribution_chart(distribution, title):
    """Create a color-coded risk distribution chart."""

    data = pd.DataFrame(
        {
            "level": list(distribution.keys()),
            "count": list(distribution.values()),
        }
    )

    figure = px.pie(
        data,
        names="level",
        values="count",
        title=title,
        hole=0.55,
        color="level",
        color_discrete_map=RISK_COLORS,
        category_orders={"level": list(RISK_LEVELS)},
    )

    figure.update_traces(
        textinfo="label+value",
    )

    figure.update_layout(
        height=350,
        margin=dict(l=15, r=15, t=50, b=15),
        legend_title_text="Level",
    )

    return figure


def main():
    """Render the security dashboard."""

    icon_col, title_col = st.columns(
        [0.7, 9.3],
        vertical_alignment="center",
    )

    with icon_col:
        st.image(str(ICON_PATH), width=65)

    with title_col:
        st.title("Network Security Dashboard")

    st.caption(
        "Network Security & Asset Visibility | "
        "Security Engineering Portfolio"
    )

    try:
        report = load_security_report(REPORT_PATH)

    except FileNotFoundError:
        st.error(
            "Security report not found. "
            "Generate security-report.json before starting "
            "the dashboard."
        )
        st.stop()

    except (OSError, ValueError) as error:
        st.error(f"Unable to load security report: {error}")
        st.stop()

    summary = get_dashboard_summary(report)
    severity_distribution = get_severity_distribution(report)
    risk_distribution = get_risk_distribution(report)
    prioritized_findings = get_prioritized_findings(report)
    asset_ranking = get_asset_risk_ranking(report)

    has_prioritization = "risk_prioritization" in report

    # Report context and navigation.
    with st.sidebar:
        st.header("Dashboard Information")

        st.markdown(
            "**Project:** Network Security & Asset Visibility"
        )

        st.markdown("**Milestone:** Security Dashboard")

        st.text(
            f"Data source: {report['data_source']}"
        )

        st.caption(
            "Contextual risk scoring is not CVSS."
        )

        st.divider()

        st.header("Navigation")

        st.markdown(
            """
            - Security Overview
            - Security Analysis
            - Asset Risk Ranking
            - Security Findings
            """
        )

        st.divider()

        st.button(
            "Refresh Report",
            key="refresh_report",
            width="stretch",
        )

    if report["data_source"] == "synthetic_lab":
        st.info(
            "Synthetic laboratory data for demonstration "
            "and security engineering purposes."
        )

    # Global security indicators.
    st.subheader("Security Overview")

    coverage = summary["coverage_percentage"]

    coverage_label = (
        f"{coverage:.1f}%"
        if coverage is not None
        else "N/A"
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Total Assets",
        summary["total_assets"],
    )

    col2.metric(
        "Affected Assets",
        summary["affected_assets"],
    )

    col3.metric(
        "Security Findings",
        summary["total_findings"],
    )

    col4.metric(
        "Configuration Coverage",
        coverage_label,
    )

    st.caption(
        "Configuration coverage does not imply "
        "security compliance."
    )

    st.divider()

    # Security severity and contextual risk analysis.
    st.subheader("Security Analysis")

    chart1, chart2 = st.columns(2)

    with chart1:
        if summary["total_findings"]:
            st.plotly_chart(
                distribution_chart(
                    severity_distribution,
                    "Findings by Severity",
                ),
                width="stretch",
            )
        else:
            st.info("No security findings available.")

    with chart2:
        if not has_prioritization:
            st.info("Risk prioritization is unavailable.")

        elif prioritized_findings:
            st.plotly_chart(
                distribution_chart(
                    risk_distribution,
                    "Contextual Risk Distribution",
                ),
                width="stretch",
            )

        else:
            st.info("No prioritized findings available.")

    # Findings grouped by security rule.
    rule_counts = Counter(
        finding["rule_id"]
        for finding in report["findings"]
    )

    if rule_counts:
        rules_df = pd.DataFrame(
            {
                "Rule": list(rule_counts.keys()),
                "Findings": list(rule_counts.values()),
            }
        )

        rule_figure = px.bar(
            rules_df,
            x="Rule",
            y="Findings",
            title="Security Findings by Rule",
            text="Findings",
            color_discrete_sequence=["#38BDF8"],
        )

        rule_figure.update_yaxes(dtick=1)

        rule_figure.update_layout(
            height=350,
            margin=dict(l=15, r=15, t=50, b=15),
        )

        st.plotly_chart(
            rule_figure,
            width="stretch",
        )

    st.divider()

    # Asset risk ranking.
    st.subheader("Asset Risk Ranking")

    if asset_ranking:
        ranking_df = pd.DataFrame(asset_ranking)

        ranking_figure = px.bar(
            ranking_df,
            x="max_risk_score",
            y="hostname",
            color="risk_priority",
            orientation="h",
            text="max_risk_score",
            color_discrete_map=RISK_COLORS,
            hover_data=[
                "asset_id",
                "total_findings",
                "asset_criticality",
            ],
            labels={
                "hostname": "Asset",
                "max_risk_score": "Maximum Risk Score",
                "risk_priority": "Risk Priority",
                "total_findings": "Total Findings",
                "asset_criticality": "Asset Criticality",
            },
        )

        ranking_figure.update_xaxes(
            range=[0, 100],
        )

        ranking_figure.update_yaxes(
            autorange="reversed",
            categoryorder="array",
            categoryarray=ranking_df["hostname"].tolist(),
        )

        ranking_figure.update_layout(
            height=350,
            margin=dict(l=15, r=15, t=20, b=15),
        )

        st.plotly_chart(
            ranking_figure,
            width="stretch",
        )

        st.dataframe(
            ranking_df,
            width="stretch",
            hide_index=True,
        )

        st.caption(
            "Assets are ranked by their highest contextual "
            "finding score, on a scale from 0 to 100."
        )

    else:
        st.info("No asset risk ranking available.")

    st.divider()

    # Interactive findings table.
    st.subheader("Security Findings")

    findings = (
        prioritized_findings
        if has_prioritization
        else report["findings"]
    )

    findings_df = pd.DataFrame(
        findings,
        columns=FINDING_COLUMNS,
    )

    if findings_df.empty:
        st.info("No security findings available.")

    else:
        filter1, filter2, filter3 = st.columns(3)

        severity_filter = filter1.multiselect(
            "Severity",
            options=list(RISK_LEVELS),
            default=list(RISK_LEVELS),
        )

        asset_filter = filter2.multiselect(
            "Asset",
            options=sorted(
                findings_df["asset_id"].unique()
            ),
            default=sorted(
                findings_df["asset_id"].unique()
            ),
        )

        mask = (
            findings_df["severity"].isin(severity_filter)
            & findings_df["asset_id"].isin(asset_filter)
        )

        if has_prioritization:
            priority_filter = filter3.multiselect(
                "Risk Priority",
                options=list(RISK_LEVELS),
                default=list(RISK_LEVELS),
            )

            mask &= findings_df["risk_priority"].isin(
                priority_filter
            )

        filtered_df = findings_df.loc[mask].copy()

        if has_prioritization:
            filtered_df = filtered_df.sort_values(
                by=[
                    "risk_score",
                    "asset_id",
                    "rule_id",
                ],
                ascending=[False, True, True],
            )

        st.caption(
            f"Displaying {len(filtered_df)} "
            f"of {len(findings_df)} findings."
        )

        st.dataframe(
            filtered_df,
            width="stretch",
            hide_index=True,
            column_config={
                "risk_score": st.column_config.ProgressColumn(
                    "Risk Score",
                    min_value=0,
                    max_value=100,
                    format="%.1f",
                ),
            },
        )

        st.download_button(
            label="Export Findings (CSV)",
            data=filtered_df.to_csv(
                index=False,
            ).encode("utf-8"),
            file_name="security-findings.csv",
            mime="text/csv",
            disabled=filtered_df.empty,
        )

    st.divider()

    st.caption(
        "Network Security & Asset Visibility | "
        "Security Engineering Portfolio"
    )


if __name__ == "__main__":
    main()