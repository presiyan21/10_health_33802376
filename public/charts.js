// public/charts.js
// Fetches weekly workout totals and draws a bar chart.

let weeklyChartInstance = null;

async function renderWeeklyChart(canvasId = 'weeklyChart') {
  const canvas = document.getElementById(canvasId);
  if (!canvas) {
    console.warn('Missing chart canvas:', canvasId);
    return;
  }

  try {
    // Request weekly summary data from the server
    const res = await fetch('/workouts/weekly-totals', {
      headers: { Accept: 'application/json' }
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const data = await res.json();
    if (!data || !Array.isArray(data.labels) || !Array.isArray(data.totals)) {
      throw new Error('Bad chart data');
    }

    const ctx = canvas.getContext('2d');

    // Drop the old chart if one exists
    if (weeklyChartInstance) weeklyChartInstance.destroy();

    // Create a simple bar chart
    weeklyChartInstance = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: data.labels,
        datasets: [
          {
            label: 'Total Minutes per Week',
            data: data.totals,
            borderWidth: 1
          }
        ]
      },
      options: {
        responsive: true,
        scales: {
          y: { beginAtZero: true }
        }
      }
    });
  } catch (err) {
    // Keep errors visible in dev tools
    console.error('Chart load failed:', err);
  }
}

window.renderWeeklyChart = renderWeeklyChart;
